#!/bin/bash
# Copyright 2017 Teradici Corporation

SERVICE="CAMIdleShutdown.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE}"
SERVICE_CONFIG_PATH="${SERVICE_PATH}.d"
SERVICE_CONFIG="${SERVICE_CONFIG_PATH}/CAMIdleShutdown.conf"
MONITOR_SCRIPT=/opt/Teradici_CAM_idle_shutdown.py

function create_monitor_script() {
    touch ${MONITOR_SCRIPT}
    chmod +x ${MONITOR_SCRIPT}
    cat <<'EOF'> ${MONITOR_SCRIPT}
#!/usr/bin/python
# Copyright 2017 Teradici Corporation
import argparse
import syslog
import time
import os
import subprocess
import re

syslog.openlog("ShutdownIdleAgent", syslog.LOG_PID)

# Shutdown the machine if it has been idle more than the specified number of minutes
# Additionally, do not log off if there is an active ssh connection, or
# there are instances of pcoip-server processes running.

## Global settings
# minimum number of minutes machine can be idle before shutting down
MIN_IDLE_WAIT_TIME=5

# maximum number of minutes machine can be idle before shutting down
MAX_IDLE_WAIT_TIME=7*24*60

# minimum number of minutes to wait between polling machine session status
MIN_POLL_INTERVAL=1

# maximum number of minutes to wait between polling machine session status
MAX_POLL_INTERVAL=60
##

def logit(message):
    """
    Log messages to Syslog
    """
    syslog.syslog(message)

def activeConnectionsExist():
    """
    Check for active PCoIP or SSH sessions
    """
    # Check for SSH Session
    sessions = subprocess.check_output(['/usr/bin/who']).split('\n')
    for session in sessions:
        # Check if session is an X-Session
        re_session = re.match(".*\((.*)\)", session)
        if re_session and ":" not in re_session.group(1)[0]:
            return True

    # Check for PCoIP Session
    proccesses = subprocess.check_output(['/bin/ps', 'aux']).split('\n')
    for proccess in proccesses:
        if 'pcoip-server' in proccess:
            return True

    return False

def getCPULoad():
    """
    Get average CPU Load over last 15 minutes
    """
    cpu_over_last_15 = 0
    uptime = subprocess.check_output('/usr/bin/uptime').strip('\n')
    re_cpu_over_last_15 = re.match(".*\d*\.\d*,\s*\d*\.\d*,\s*(\d*\.\d*)", uptime)
    if re_cpu_over_last_15:
        cpu_over_last_15 = float(re_cpu_over_last_15.group(1))*100
    return cpu_over_last_15

def parseArgs():
    """
    Parse Input Arguements
    """
    # Default Values
    pollInterval = 15
    waitTime = 60
    cpuThreshold = 20

    parser = argparse.ArgumentParser(
        description="Teradici provided Service to monitor active sessions and CPU usage to shutdown VM when not in use",
        usage="Teradici_CAM_Idle_Shutdown.py: [ <wait-minutes> <poll-interval> <cpu-threshold> ]"
    )
    parser.add_argument(
        'waitTime',
        metavar='waitTime',
        type=int,
        nargs=1,
        choices=range(
            MIN_IDLE_WAIT_TIME,
            MAX_IDLE_WAIT_TIME
        ),
        default=waitTime,
        help="The Number of minutes a machine must be idle before shutting off"
    )
    parser.add_argument(
        'pollInterval',
        metavar='pollInterval',
        type=int,
        nargs=1,
        choices=range(
            MIN_POLL_INTERVAL,
            MAX_POLL_INTERVAL
        ),
        default=pollInterval,
        help="The Number of minutes between checking for the idle CPU Usage"
    )
    parser.add_argument(
        'cpuThreshold',
        metavar='cpuThreshold',
        type=int,
        nargs=1,
        choices=range(0, 100),
        default=cpuThreshold,
        help="The Percentage CPU Usage below where the machine is considered to be idling"
    )
    args = parser.parse_args()
    return (args.pollInterval[0]*60, args.cpuThreshold[0], args.waitTime[0]*60)

def main():
    """
    Main function, monitor active sessions and CPU usage and shutdown when appropriate
    """
    pollInterval, cpuThreshold, waitTime = parseArgs()
    logit(  ("Monitoring system for idle state every {POLL_INTERVAL} " +
            "minutes and will shutdown machine if idle (CPU <" +
            " {CPU_THRESHOLD}% utilization) for {WAIT_TIME} minutes.").format(
                POLL_INTERVAL= pollInterval/60,
                CPU_THRESHOLD= cpuThreshold,
                WAIT_TIME= waitTime/60
            )
    )

    startTime = None
    while True:
        if activeConnectionsExist():
            logit("Sessions still active, not shutting down")
            startTime = None
        else:
            cpuUsage = getCPULoad()
            if cpuUsage < cpuThreshold:
                logit('CPU usage is now {cpu}%, it is below idle threshold'.format(
                        cpu=cpuUsage
                ))
                if not startTime:
                    startTime = time.time()
                currentTime = time.time()
                elapsedTime = currentTime - startTime
                logit("CPU has been idle for at least {} minutes".format(
                    int(elapsedTime/60)
                ))
                if elapsedTime > waitTime:
                    logit("CPU has been idle for more than {} minutes, shutting down".format(
                        waitTime
                    ))
                    os.system('/sbin/shutdown')
            else:
                logit("CPU usage is now {cpu}%, CPU is active".format(
                    cpu=cpuUsage
                ))
                startTime = None
        time.sleep(pollInterval)

if __name__=="__main__":
    main()
EOF
}

function install() {
    echo "Installing"
    touch ${SERVICE_PATH}
    chmod 664 ${SERVICE_PATH}
    mkdir -p ${SERVICE_CONFIG_PATH}
    touch ${SERVICE_CONFIG}
    chmod 664 ${SERVICE_CONFIG}
    create_monitor_script
    cat <<EOF> ${SERVICE_PATH}
[Unit]
Description=Teradici CAM Idle Shutdown monitoring service
After=pcoip.service

[Service]
Type=simple
ExecStart=/usr/bin/sudo /usr/bin/python ${MONITOR_SCRIPT} \${MinutesIdleBeforeShutdown} \${PollingIntervalMinutes} \${CPUUtilizationLimit}
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
    cat <<EOF> ${SERVICE_CONFIG}
[Service]
Environment="PollingIntervalMinutes=15"
Environment="MinutesIdleBeforeShutdown=60"
Environment="CPUUtilizationLimit=20"
EOF
    echo "Starting Service"
    systemctl daemon-reload
    systemctl enable ${SERVICE}
    systemctl start ${SERVICE}
}

function remove() {
    echo "Removing"
    systemctl stop ${SERVICE}
    systemctl disable ${SERVICE}
    rm -rf ${SERVICE_PATH}*
    rm ${MONITOR_SCRIPT}
    systemctl daemon-reload
}

function should_be_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "You must be root for this operation"
        exit 1
    fi
}

function main() {
    should_be_root
    command=$1
    case "$command" in
        "--install" | "-install" | "-i")
            install
            ;;
        "--remove" | "-remove" | "-r")
            remove
            ;;
        *)
            echo "Unkown command, use -install or -remove"
            ;;
    esac
}

main $@
