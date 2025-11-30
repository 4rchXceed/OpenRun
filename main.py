from ui.ui import panel_app
import panel as pn
import lib.webserver
import lib.libvirt
import sys
import signal

def interrupt_callback():
    """Detects if the script is interrupted by Ctrl+C."""
    print("Server stopped by user.")
    lib.webserver.stop_trigger = True
    if lib.libvirt.instance:
        lib.libvirt.instance.stop_threads()
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, interrupt_callback)
    pn.serve(panels={"/": panel_app}, show=True, title="OpenRunVM",websocket_max_message_size=10485760000, max_buffer_size=10485760000, max_body_size=10485760000, max_header_size=10485760000)


if __name__ == "__main__":
    main()