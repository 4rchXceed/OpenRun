from tempfile import template
from urllib.parse import urlparse
import panel as pn
import sys
from lib.libvirt import LibvirtVMManager
from lib.requirements import check_requirements
import lib.webserver
import json
import time
import os
import socket
import geoip2.database
import csv
import ipaddress
import datetime
from vncdotool.api import connect
import threading
from ui.ai import check_single_action

pn.extension()

final_dead_warning_shown = False
dead_warning_shown = False
is_running = False
old_session_data = set()
vm_manager = LibvirtVMManager()
geoip_reader = None
countries_emojis_kv = {}
countries_emojis = []

NETWORK_EXCLUDE = {
    "ip_cidr": ["192.168.0.0/16"],
    "ip": [
        # Special IPs
        "0.0.0.0",
        "127.0.0.1",
    ],
    "fqdn": [
        # Special FQDNs
        "localhost",
        "akamaitechnologies.com",
        "microsoft.com",
        "windowsupdate.com",
    ],
}

replay_data: dict[str, any] = {}
last_replay_update = 0


if not check_requirements():
    pn.pane.Markdown(
        "**Please install the missing requirements and try again.**"
    ).servable()
    sys.exit(1)

reader = geoip2.database.Reader("db/GeoLite2-Country.mmdb")

with open("db/countries.json", "r", encoding="utf-8") as f:
    countries_emojis = json.load(f)
    countries_emojis_kv = {v["isoCode"]: k for k, v in enumerate(countries_emojis)}

with open("db/msft-public-ips.csv", "r", encoding="utf-8") as f:
    csv_reader = csv.reader(f)
    next(csv_reader)
    for row in csv_reader:
        if row and row[0]:
            ip_range = row[0].strip()
            NETWORK_EXCLUDE["ip_cidr"].append(ip_range)


def closest(array, nbr):
    closest_value = min(array, key=lambda x: abs(x - nbr))
    return closest_value


client = None
screenshot_thread = None


def connect_vnc(address):
    global client
    client = connect(address)
    client.connect(address.split(":")[0], address.split(":")[1])


def vnc_screenshot_loop(dir):
    global screenshot_thread
    if not os.path.exists(dir):
        os.makedirs(dir)
    if client.protocol.connected == 1 and is_running:
        client.protocol.captureScreen(fp=f"{dir}/{str(round(time.time()))}.png")
        screenshot_thread = threading.Timer(3, vnc_screenshot_loop, args=(dir,))
        screenshot_thread.start()


def create_ui(template=None):
    global final_dead_warning_shown, dead_warning_shown, is_running, old_session_data

    tabs = pn.Tabs()
    analysis_tab = pn.Column()
    process_tree_tab = pn.Column()
    topbar = pn.Row()

    currentscreenshot_img = pn.pane.PNG(width=400)
    currentscreenshot_window = pn.layout.FloatPanel(
        currentscreenshot_img, name="Current Screenshot", margin=20
    )

    disclaimer = """
    This is for MALWARE analysis.
    Do NOT use this program if you don't have a VPN.
    It could cause your IP to be exposed.
    (Or use it without a VPN if you don't care abt getting doxxed lol)
    Personally, I reccomend ProtonVPN. It's free :)
    \n
    https://protonvpn.com/
    """

    help_text = """
    Available actions:
    1. setup: run OpenRun setup
    2. Run: start the VM
    3. Stop: stop the VM
    4. Install Script: Install the helper script (require manual intervention AND is needed to run the VM!)

    See docs/ for more info.
    """

    disclaimer_pane = pn.pane.Markdown(disclaimer, width=500)
    help_pane = pn.pane.Markdown(help_text, width=500)
    os_select = pn.widgets.Select(name="OS", options=["win11", "win10"])
    iso_input = pn.widgets.TextInput(name="ISO file path")
    ip_input = pn.widgets.TextInput(name="IP Address", value="192.168.222.1")
    setup_button = pn.widgets.Button(name="Setup VM", button_type="primary")
    upload_input = pn.widgets.FileInput(
        name="Upload File (That you suspect is malicious)", accept=".zip"
    )
    run_button = pn.widgets.Button(name="Run VM", button_type="success")
    stop_button = pn.widgets.Button(name="Stop VM", button_type="danger")
    install_script = pn.widgets.Button(name="Install VM Script", button_type="primary")
    finish_install_btn = pn.widgets.Button(
        name="Finish Install (Backup)", button_type="primary"
    )
    output = pn.pane.Markdown("")

    replay_selector = pn.widgets.Select(name="Replay", options=[])
    replay_progress_bar = pn.widgets.FloatSlider(name="Replay Progress", value=0)

    sessions_time_relation = initialize_session_select(replay_selector)
    replay_selector.value = (
        replay_selector.options[0] if replay_selector.options else "No sessions found"
    )

    status_text = pn.pane.Markdown("", width=300)

    def select_replay(event):
        global replay_data
        selected_session = sessions_time_relation.get(replay_selector.value)
        if selected_session:
            replay_progress_bar.value = 0
            output.object = f"**Selected Replay:** {selected_session}"
            with open(f"db/sessions/{selected_session}.json", "r") as f:
                replay_data = json.load(f)
            output.object += f"\n\n**Loaded Replay:**\n{selected_session}"
            first = int(list(replay_data.keys())[0])
            last = int(list(replay_data.keys())[-1])
            between = last - first
            replay_progress_bar.start = 0
            replay_progress_bar.end = between
            replay_progress_bar.value = 0

    select_replay(None)

    def finish_install(event):
        os_choice = os_select.value
        print(f"Finishing install for {os_choice}...")
        if os_choice not in ["win11", "win10"]:
            print(f"ERROR: Unsupported OS type: {os_choice}")
            return
        vm_manager.create_snapshot(os_choice)

    def replay_progress_callback(event):
        global last_replay_update, replay_data
        # if time.time() - last_replay_update < 3: # This avoids spamming updates (the progress will update very frequently when you move the slider), also the processing needs a lot of time due to the panel elements added
        #     return
        last_replay_update = time.time()
        types = ["proc", "net", "proctree", "reg", "httpdump"]
        types_found = {}
        if replay_data:
            keys = [int(k) for k in replay_data.keys()]
            current = int(list(replay_data.keys())[0]) + replay_progress_bar.value
            keys_up_to_current = [k for k in keys if k <= current]
            types_found = {}
            for k in keys_up_to_current:
                val = replay_data[str(k)]
                types_found[k] = val

            screenshot_dir = f"db/sessions/screenshots/{sessions_time_relation[replay_selector.value]}"
            if os.path.exists(screenshot_dir):
                times = [
                    int(v.split(".")[0])
                    for v in os.listdir(screenshot_dir)
                    if v.endswith(".png")
                ]
                times_up_to_current = [t for t in times if t <= current]
                if times_up_to_current:
                    closest_time = max(times_up_to_current)
                    currentscreenshot_img.object = (
                        f"{screenshot_dir}/{closest_time}.png"
                    )
                else:
                    currentscreenshot_img.object = None
            else:
                currentscreenshot_img.object = None

            print("Processing session data...")
            proc_container.clear()
            net_container.clear()
            http_container.clear()
            reg_container.clear()
            # Process all data up to 'current'
            for k in sorted(types_found.keys()):
                process_session_data(
                    {}, types_found[k], k - int(list(replay_data.keys())[0])
                )

    if template is None:
        template = pn.template.BootstrapTemplate(title="OpenRunVM")

    def make_proc_detail(proc):
        return (
            f"**Process Name:** {proc.get('ProcessName', 'N/A')}\n\n"
            f"**PID:** {proc.get('Id', 'N/A')}\n\n"
            f"**Path:** {proc.get('Path', 'N/A')}\n\n"
            f"**Parent Process Name:** {proc.get('ParentProcessName', 'N/A')}\n\n"
            f"**Parent Process ID:** {proc.get('ParentProcessId', 'N/A')}\n\n"
            f"**Command Line:** {proc.get('CommandLine', 'N/A')}\n\n"
        )

    def make_reg_detail(reg):
        return (
            f"**Path:** {reg.get('PSPath', 'N/A')}\n\n"
            f"**Name:** {reg.get('Name', 'N/A')}\n\n"
            f"**Value:** {reg.get('Value', 'N/A')}"
        )

    def ask_single_action_callback(proc: dict):
        print("Asking AI about single action...")
        summary = f""
        for key in proc.keys():
            summary += f"{key}: {proc[key]}\n"
        status_text.object = "**Asking AI...**"
        is_malicious, explanation = check_single_action(summary)
        status_text.object = ""
        make_ai_callback(is_malicious, explanation)

    def make_ai_callback(is_malicious, explanation):
        template.modal[0].clear()
        template.modal[0].append(
            f"**Is Malicious:** {'Yes' if is_malicious else 'No'}\n\n**Explanation:** {explanation}"
        )
        template.open_modal()

    def make_net_detail(net):
        return (
            f"**LocalAddress:** {net.get('LocalAddress', 'N/A')}\n\n"
            f"**LocalPort:** {net.get('LocalPort', 'N/A')}\n\n"
            f"**RemoteAddress:** {net.get('RemoteAddress', 'N/A')}\n\n"
            f"**RemotePort:** {net.get('RemotePort', 'N/A')}\n\n"
            f"**State:** {net.get('State', 'N/A')}\n\n"
            f"**Protocol:** {net.get('Protocol', 'N/A')}\n\n"
            f"**OwningProcess:** {net.get('OwningProcessName', 'N/A')}\n\n"
            f"**HostName:** {net.get('HostName', 'Unknown')}"
        )

    def make_http_detail(http):
        final_md = ""
        for header in http.get("Headers", {}).items():
            final_md += f"**{header[0]}:** {header[1]}\n\n"
        return (
            f"**URL:** {http.get('Url', 'N/A')}\n\n"
            f"**Method:** {http.get('Method', 'N/A')}\n\n"
            f"**Headers:** {final_md}"
            f"**Body:** {http.get('Body', 'N/A')}\n\n"
        )

    def final_warning_detail():
        return "WE LOST OUR SPY... FOREVERRRRR, THE ENEMY HAS WON!!!!! (or you just shut down the vm, lemme check)"

    os_choice = "None"

    def install_script_callback(event):
        global is_running
        os_choice = os_select.value
        if not is_running:
            output.object = "**Running VM...**"
            status = vm_manager.only_run_vm(os_choice)
            if status:
                output.object = "**VM is running successfully.**"
            else:
                output.object = "**Failed to run VM (check cli output)**"
                return
        if lib.webserver.srv_ip == "localhost":
            output.object = "**Server IP not found, plz check the VM connection ext.**"
            return

        output.object = f"""
            Now, you need to install the OS manually.
            After the installation is complete, press Win+R and run:
            {lib.webserver.setupwin_cmd.decode()}

            (To get the command to copy, go to: http://{lib.webserver.srv_ip}:8000/inst_win_cmd)
            This will run the script from the host webserver as administrator inside the VM.
            """

    def setup_vm_callback(event):
        nonlocal os_choice
        os_choice = os_select.value
        isofile = iso_input.value
        ip = ip_input.value
        if os_choice not in ["win11", "win10"]:
            output.object = "**Unsupported OS.**"
            return
        result = vm_manager.setup_vm(os_choice, isofile, ip=ip)
        if not result:
            output.object = f"Failed to setup VM for {os_choice}."
            return
        output.object = (
            f"VM setup for {os_choice} started with ISO: {isofile}\n{result}"
        )

    def run_vm_callback(event):
        nonlocal os_choice
        global is_running, screenshot_thread
        print("Uploading file...")
        upload_input.save("db/current.zip")
        os_choice = os_select.value
        if os_choice not in ["win11", "win10"]:
            output.object = "**Unsupported OS.**"
            return
        result = vm_manager.run_vm(os_choice, "db/current.zip")
        if not result:
            output.object = f"Failed to start VM for {os_choice}."
            return
        is_running = True
        connect_vnc("127.0.0.1:5901")
        screenshot_thread = threading.Timer(
            3,
            vnc_screenshot_loop,
            args=(f"db/sessions/screenshots/{lib.webserver.session}",),
        )
        screenshot_thread.start()
        output.object = f"VM for {os_choice} is running with ZIP: db/current.zip"

    def stop_operation_callback(event):
        global is_running
        if is_running:
            lib.webserver.is_session_active = False
            vm_manager.vnc_thread.join()
            is_running = False
            output.object = f"VM for {os_choice} has been stopped."
            initialize_session_select(replay_selector)
        else:
            output.object = "No VM is currently running."

    setup_button.on_click(setup_vm_callback)
    run_button.on_click(run_vm_callback)
    install_script.on_click(install_script_callback)
    stop_button.on_click(stop_operation_callback)
    finish_install_btn.on_click(finish_install)

    replay_selector.param.watch(select_replay, "value")
    replay_progress_bar.param.watch(replay_progress_callback, "value")

    proc_container = pn.Row()
    reg_container = pn.Row()
    net_container = pn.Row()
    http_container = pn.Row()
    proc_tree_container = pn.Column()

    def update_analyze():
        global final_dead_warning_shown, dead_warning_shown, old_session_data
        if is_running:
            if lib.webserver.is_alive:
                # if time.time() - lib.webserver.last_keepalive > 10:
                #     if not dead_warning_shown:
                #         if pn.state.notifications is not None:
                #             pn.state.notifications.warning("Roger, roger, do you hear me? Fuuuck we lost connection to the vm intern script.........")
                #         dead_warning_shown = True
                # if time.time() - lib.webserver.last_keepalive > 30:
                #     if not final_dead_warning_shown:
                #         template.modal[0].append(final_warning_detail())
                #         template.open_modal()
                #         if pn.state.notifications is not None:
                #             pn.state.notifications.info("I'm checking the VM status... 4.00 sec plz")
                #         time.sleep(4)
                #         if vm_manager.check_vm_status(os_choice):
                #             if pn.state.notifications is not None:
                #                 pn.state.notifications.success("My bad, ur cooked")
                #         else:
                #             if pn.state.notifications is not None:
                #                 pn.state.notifications.error("The VM is not running, please check the VM status. (Aka: You're not cooked)")
                #         final_dead_warning_shown = True
                print(
                    f"Loading session data from ./db/sessions/{lib.webserver.session}.json"
                )
                with open(f"./db/sessions/{lib.webserver.session}.json", "r") as f:
                    session_data: dict[str, any] = json.load(f)

                    print(
                        f"Loading session data from ./db/sessions/{lib.webserver.session}.json"
                    )
                    with open(f"./db/sessions/{lib.webserver.session}.json", "r") as f:
                        session_data = json.load(f)

                    if not isinstance(old_session_data, set):
                        old_session_data = set()

                    new_keys = sorted(
                        set(session_data.keys()) - old_session_data, key=float
                    )
                    if new_keys:
                        for key in new_keys:
                            data = session_data[key]
                            time_since_start = int(key) - int(
                                list(session_data.keys())[0]
                            )
                            process_session_data(session_data, data, time_since_start)
                        old_session_data.update(new_keys)

    def process_session_data(session_data, data, time_since_start):
        if type(data.get("data")) == dict:
            data = {"data": [data.get("data")], "type": data.get("type")}
        if data.get("type") == "proctree":
            ignore_pids = []
            found_first = False
            i = 0
            session_data_values = list(session_data.values())
            while not found_first:
                try:
                    current_data = session_data_values[i]
                    i += 1
                    if current_data.get("type") == "proctree":
                        if type(current_data.get("data")) == dict:
                            current_data = {
                                "data": [current_data.get("data")],
                                "type": current_data.get("type"),
                            }
                        found_first = True

                        def analyze_pids(elements):
                            for elem in elements:
                                elem_id = elem.get("pid")
                                if elem_id is not None:
                                    ignore_pids.append(elem_id)
                                if elem.get("childs"):
                                    analyze_pids(elem.get("childs", []))

                        analyze_pids(current_data.get("data", []))
                except IndexError:
                    break

            def handle_process(procs, element: pn.Column, level=0):
                for proc in procs:
                    if (
                        proc.get("pid") in ignore_pids
                        and len(proc.get("childs", [])) == 0
                    ):
                        continue
                    margin_left = 20 * level
                    element.append(
                        pn.Card(
                            pn.pane.Markdown(
                                f"**Name:** {proc.get('name', 'Unknown')}\n**PID:** {proc.get('id', 'Unknown')}\n**Cli:** {proc.get('cmdline', 'Unknown')}\n"
                            ),
                            title=f"{time_since_start}s: Process",
                            width=1000,
                            margin=(5, 0, 5, margin_left),
                        )
                    )
                    if proc.get("childs"):
                        handle_process(proc.get("childs", []), element, level + 1)

            proc_tree_container.clear()
            handle_process(data.get("data"), proc_tree_container)
        if data.get("type") == "proc":
            for proc in data.get("data", []):

                def view_detail_callback(event, proc=proc):
                    template.modal[0].clear()
                    template.modal[0].append(make_proc_detail(proc))
                    template.open_modal()

                card = pn.Card(
                    pn.pane.Markdown(
                        f"**Process:** {proc.get('ProcessName', 'Unknown')} {proc.get('CommandLine', '')}\n **Started By:** {proc.get('ParentProcessName', 'Unknown')}"
                    ),
                    pn.widgets.Button(
                        name="View Detail",
                        button_type="primary",
                        width=100,
                        on_click=view_detail_callback,
                    ),
                    pn.widgets.Button(
                        name="Is this malicious? [AI]",
                        button_type="primary",
                        width=100,
                        on_click=lambda event, proc=proc: ask_single_action_callback(
                            proc
                        ),
                    ),
                    title=f"{time_since_start}s: Process",
                    width=300,
                    margin=(5, 5),
                )
                proc_container.insert(0, card)
        elif data.get("type") == "reg":
            for reg in data.get("data", []):

                def view_detail_callback(event, reg=reg):
                    template.modal[0].clear()
                    template.modal[0].append(make_reg_detail(reg))
                    template.open_modal()

                card = pn.Card(
                    pn.pane.Markdown(
                        f"**Key:** {reg.get('Name', 'Unknown')}\n **Value (10chars):** {reg.get('Value', 'Unknown')[:10]}"
                    ),
                    pn.widgets.Button(
                        name="View Detail",
                        button_type="primary",
                        width=100,
                        on_click=view_detail_callback,
                    ),
                    pn.widgets.Button(
                        name="Is this malicious? [AI]",
                        button_type="primary",
                        width=100,
                        on_click=lambda event, reg=reg: ask_single_action_callback(reg),
                    ),
                    title=f"{time_since_start}s: Registry",
                    width=300,
                    margin=(5, 5),
                )
                reg_container.insert(0, card)
        elif data.get("type") == "httpdump":
            for http in data.get("data", []):
                parsed_uri = urlparse(http.get("Url", ""))
                try:
                    ip = (
                        socket.gethostbyname(parsed_uri.netloc)
                        if parsed_uri.netloc
                        else "Unknown"
                    )
                except socket.gaierror as e:
                    try:
                        if ":" in parsed_uri.netloc:
                            ip = str(
                                ipaddress.ip_address(parsed_uri.netloc.split(":")[0])
                            )
                        else:
                            ip = str(ipaddress.ip_address(parsed_uri.netloc))
                    except ValueError:
                        ip = None
                if ip is None or (
                    not any(
                        ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
                        for cidr in NETWORK_EXCLUDE["ip_cidr"]
                    )
                    and not ip in NETWORK_EXCLUDE["ip"]
                    and all(
                        fqdn not in (parsed_uri.hostname or "")
                        for fqdn in NETWORK_EXCLUDE["fqdn"]
                    )
                ):

                    def view_detail_callback(event, http=http):
                        template.modal[0].clear()
                        template.modal[0].append(make_http_detail(http))
                        template.open_modal()

                    card = pn.Card(
                        pn.pane.Markdown(
                            f"**URL:** {http.get('Url', 'Unknown')}\n **Method:** {http.get('Method', 'Unknown')}\n **Body:** {(http.get('Body', 'Unknown')[:100])}"
                        ),
                        pn.widgets.Button(
                            name="View Detail",
                            button_type="primary",
                            width=100,
                            on_click=view_detail_callback,
                        ),
                        pn.widgets.Button(
                            name="Is this malicious? [AI]",
                            button_type="primary",
                            width=100,
                            on_click=lambda event, http=http: ask_single_action_callback(
                                {
                                    "Url": http.get("Url", "N/A"),
                                    "Method": http.get("Method", "N/A"),
                                    "Body": http.get("Body", "N/A")[:500],
                                }
                            ),
                        ),
                        title=f"{time_since_start}s: HTTP",
                        width=300,
                        margin=(5, 5),
                    )
                    http_container.insert(0, card)
        elif data.get("type") == "net":
            for net in data.get("data", []):

                def view_detail_callback(event, net=net):
                    try:
                        template.modal[0].clear()
                        template.modal[0].append(make_net_detail(net))
                        template.open_modal()
                    except Exception as e:
                        print("Error occurred:", e)

                remote_address = net.get("HostName", None)
                if (
                    not any(
                        ipaddress.ip_address(net.get("RemoteAddress"))
                        in ipaddress.ip_network(cidr)
                        for cidr in NETWORK_EXCLUDE["ip_cidr"]
                    )
                    and not net.get("RemoteAddress") in NETWORK_EXCLUDE["ip"]
                    and all(
                        fqdn not in (remote_address or "")
                        for fqdn in NETWORK_EXCLUDE["fqdn"]
                    )
                ):
                    if not remote_address:
                        remote_address = net.get("RemoteAddress", "Unknown")
                    try:
                        response = reader.country(net.get("RemoteAddress"))
                    except geoip2.errors.AddressNotFoundError:
                        response = None
                    iso_code = response.country.iso_code if response != None else "N/A"
                    country_id = countries_emojis_kv.get(iso_code, -1)
                    country = countries_emojis[country_id]
                    card = pn.Card(
                        pn.pane.Markdown(
                            f"**RemoteServer ({country['emojiFlag']} {country['country']}):** {remote_address}\n**OwningProcess:** {net.get('OwningProcessName', 'Unknown')}"
                        ),
                        pn.widgets.Button(
                            name="View Detail",
                            button_type="primary",
                            width=100,
                            on_click=view_detail_callback,
                        ),
                        pn.widgets.Button(
                            name="Is this malicious? [AI]",
                            button_type="primary",
                            width=100,
                            on_click=lambda _, net=net: ask_single_action_callback(net),
                        ),
                        title=f"{time_since_start}s: Network",
                        width=300,
                        margin=(5, 5),
                    )
                    net_container.insert(0, card)

    template.modal.append(pn.Column())

    topbar.append(replay_progress_bar)
    topbar.append(replay_selector)
    topbar.append(status_text)

    main_tab = pn.Column(
        disclaimer_pane,
        help_pane,
        os_select,
        iso_input,
        ip_input,
        setup_button,
        upload_input,
        run_button,
        stop_button,
        install_script,
        finish_install_btn,
        output,
        width=600,
    )

    analysis_tab.append(net_container)
    analysis_tab.append(proc_container)
    analysis_tab.append(reg_container)
    analysis_tab.append(http_container)
    process_tree_tab.append(proc_tree_container)

    tabs.append(("Main", main_tab))
    tabs.append(("Analysis", analysis_tab))
    tabs.append(("Process Tree", process_tree_tab))

    template.main.append(tabs)
    template.main.insert(0, topbar)
    template.main.append(currentscreenshot_window)

    template.update_analyze = update_analyze

    return template


def initialize_session_select(replay_selector):
    sessions_time_relation = {}
    sessions = os.listdir("db/sessions")
    for session in sessions:
        if not session.endswith(".json"):
            continue
        created_time = os.path.getctime(os.path.join("db/sessions", session))
        val = datetime.datetime.fromtimestamp(created_time).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        replay_selector.options.append(val)
        sessions_time_relation[val] = session.split(".")[0]
    return sessions_time_relation


def panel_app():
    template = create_ui()
    pn.state.add_periodic_callback(template.update_analyze, period=1000)
    return template
