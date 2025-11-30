# OpenRun Usage Guide

## Installation
Follow the steps in the [Getting Started Guide](GETSTARTED.md) to set up OpenRun.

## The tabs

### Main Tab
The Main Tab is the central hub for managing your virtual machine, you can:
- Choose the OS (Win10, Win11) -> You can have max 2 VMs (one for each OS).
- Enter a path to an ISO file. [Only required for Setup]
- Enter an IP adress for the VM. [Only required for Setup]
- Start the setup process.
- Choose a malware sample to run on the VM.
- Start/Stop the VM, ONLY WITH A SAMPLE SELECTED.
- Install the sniffer service on the VM.
- Create a snapshot of the current VM state.

#### Main Tab Notes
- The snapshot is reverted automatically when you start the VM with a sample. NOT AFTER YOU STOP IT!
- You can only have one VM running at a time.
- The sniffer service is only required if you want to capture network/process data/alot of other things from the VM.

### Analysis Tab

The Analysis Tab is where you can view the data captured from the VM. There's 4 main sections:
- Network: View all network traffic captured from the VM. (TCP, without content). Sometimes the sniffer can't find the domain (website name) for an IP. Here's the infomations you have:
    - Time: When (seconds after start) the packet was captured.
    - LocalAddress: The VM's IP address. (useless, always the same)
    - LocalPort: The port used on the VM. (sometimes useful)
    - RemoteAddress: The IP address of the remote server.
    - RemotePort: The port used on the remote server.
    - State: The TCP state as number
    - Protocol: The Protocol used (always TCP)
    - OwnerProcess: The process on the VM that created the packet.
    - HostName: The domain name of the remote server (if found).
    - You have a flag next to the summary that indicates the location of the remote server: The "default" one is Zimbabwe, so if you see that, it's probably because the sniffer couldn't find the real location.
- Processes: View all started/stopped processes on the VM.
    - Time: When (seconds after start) the process was started/stopped.
    - PID: The Process ID.
    - Path: The full path of the process executable.
    - Parent Process Name: The name of the parent process.
    - Parent Process ID: The Process ID of the parent process.
    - Command Line: The command line used to start the process.
- Registry: View suspicious registry changes on the VM. (see below for more details)
    - Time: When (seconds after start) the registry change was made.
    - Path: The full path of the registry key.
    - Value: The value of the registry key.
- HTTP: Decrypted HTTPS/HTTP traffic from the VM, using MITMProxy.
    - Time: When (seconds after start) the HTTP request was made.
    - URL: The full URL of the request.
    - Method: The HTTP method used (GET, POST, etc).
    - Headers: The HTTP headers of the request.
    - Host: The host of the request.
    - Content-Length: The length of the request content.
    - Connection: The connection type (keep-alive, close, etc).
    - Body: The body of the request.

#### Registry Notes
OpenRun counts a registry change as "suspicious" if it matches one of the following registry paths:
- `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM:\SYSTEM\CurrentControlSet\Services`
- `HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
- `HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`

### Process Tree Tab
The Process Tree Tab shows a tree view of all processes started on the VM, along with their parent-child relationships. This allows you to easily see which processes were started by which parent processes, helping you identify potentially malicious behavior
.
One entry contains: 
- Name, PID, CLI

## Replay system
The Replay system allows you to record and replay the execution of a malware sample on the VM. This is useful for debugging and analysis, as you can see exactly what the malware did during its execution.

For now, when there's a lot of actions, the replay can be a bit slow.

### How to use the Replay system
Select the replay (by time) in the dropdown menu.
Scroll down, and you'll find a "browser-window", this will show screenshots taken during the execution of the sample. (Drag it in the top left corner to see it better).

To "start" a replay, move the slider "Replay Progress" to the right, this will move the replay forward in time, updating the screenshot and all data in the Analysis tab to match the selected time.

This will "replay" the execution of the sample up to the selected time in the Analysis/Process Tree tabs.

## AI-Mode

The AI-Mode allows you to get a summary of the behavior of one action (network/process/registry/http) captured from the VM.
To use the AI-Mode, click in "Is This malicious?" button next to the action you want to analyze.

It gives:
- Is Malicious: Yes/No
- Explanation: A short explanation of why the action is considered malicious or not.

### Installation of the AI-Mode

The AI-Mode requires a running Ollama instance.

Set the model you want to use in ".env" file (default: qwen2.5:14b).

You can find more information about Ollama [here](https://ollama.com/download).

### Some words about the AI-Mode

The AI-Mode doesn't have the full context, so it sucks, for now. Use it as a helper, not as a final verdict.

Sometimes, the model can send an invalid response, in this case, just try again. (You need a ~>8b model for better results).

## TODOs (If I find the time)
See the [TODO.md](TODO.md) file.