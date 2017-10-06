#!/bin/bash
# Copyright 2017 Teradici Corporation

SERVICE="CAMIdleShutdown.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE}"
SERVICE_CONFIG_PATH="${SERVICE_PATH}.d"
SERVICE_CONFIG="${SERVICE_CONFIG_PATH}/CAMIdleShutdown.conf"
MONITOR_SCRIPT=/opt/Teradici_CAM_idle_shutdown.py

function create_monitor_script() {
    touch ${MONITOR_SCRIPT}
    chmod 644 ${MONITOR_SCRIPT}
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

# Used for measuring CPU Usage, initialize to 0
BusyTime_last = BusyTime_now = IdleTime_now = IdleTime_last = 0

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
    Get average CPU Load since last Poll

    For each CPU there are 7 counters:
        UserTime, NiceTime, SystemTime, IdleTime, IOwaitTime, IRQTime, and SoftIRQTime
    The average CPU usage since startup for any given sample is therefore simply:

        Usage = (1 - IdleTime/(IdleTime + BusyTime))*100%, where
        BusyTime = UserTime + NiceTime + SystemTime + IOwaitTime + IRQTime + SoftIRQTime

    This is pretty straight forward, but what is needed is actually the average CPU usage
    over the sampling interval. To get this, we need to values of the IdleTime and BusyTime
    of the previous sample. This leads to the equation:

        Usage_avg   = Change in CPU Stat Counter
                    = 1 - (IdleTime_now - IdleTime_last)/((IdleTime_now + BusyTime_now) - (IdleTime_last + BusyTime_last))
                    = ((IdleTime_now + BusyTime_now) - (IdleTime_last + BusyTime_last))/((IdleTime_now + BusyTime_now) - (IdleTime_last + BusyTime_last))
                        - (IdleTime_now - IdleTime_last)/((IdleTime_now + BusyTime_now) - (IdleTime_last + BusyTime_last))
                    = (IdleTime_now + BusyTime_now -IdleTime_last - BusyTime_last - IdleTime_now + IdleTime_last)/((IdleTime_now + BusyTime_now) - (IdleTime_last + BusyTime_last))
                    = (BusyTime_now - BusyTime_last)/((IdleTime_now + BusyTime_now) - (IdleTime_last + BusyTime_last))
    """
    global BusyTime_last, BusyTime_now, IdleTime_now, IdleTime_last
    cpu_usage = 0
    cpu_stats = ''
    proc_stats = subprocess.check_output(['/bin/cat','/proc/stat']).split('\n')
    for stat in proc_stats:
        if re.match('^cpu[^\d]+', stat):
            cpu_stats = stat
            break

    re_cpu_stats = re.match('^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+', cpu_stats)
    if re_cpu_stats:
        user_cpu = float(re_cpu_stats.group(1))
        nice_cpu = float(re_cpu_stats.group(2))
        system_cpu = float(re_cpu_stats.group(3))
        idle_cpu = float(re_cpu_stats.group(4))
        iowait_cpu = float(re_cpu_stats.group(5))
        irq_cpu = float(re_cpu_stats.group(6))
        softirq_cpu = float(re_cpu_stats.group(7))

        IdleTime_now = idle_cpu
        BusyTime_now = user_cpu + nice_cpu + system_cpu + iowait_cpu + irq_cpu + softirq_cpu

        cpu_usage = 100.0* (BusyTime_now - BusyTime_last)/((IdleTime_now + BusyTime_now) - (IdleTime_last + BusyTime_last))
        
        BusyTime_last = BusyTime_now
        IdleTime_last = IdleTime_now
    
    return round(cpu_usage, 2)

def getSettings():
    """
    Get Settings from environment
    """
    # Load Values, use Defaults if needed, convert to seconds as needed
    pollInterval = float(os.environ.get('PollingIntervalMinutes', 15))*60
    waitTime = float(os.environ.get('MinutesIdleBeforeShutdown', 60))*60
    cpuThreshold = float(os.environ.get('CPUUtilizationLimit', 20))
    
    return (pollInterval, cpuThreshold, waitTime)

def main():
    """
    Main function, monitor active sessions and CPU usage and shutdown when appropriate
    """
    pollInterval, cpuThreshold, waitTime = getSettings()
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
            logit("Sessions is active, not shutting down")
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
    chmod 644 ${SERVICE_PATH}
    mkdir -p ${SERVICE_CONFIG_PATH}
    touch ${SERVICE_CONFIG}
    chmod 644 ${SERVICE_CONFIG}
    create_monitor_script
    cat <<EOF> ${SERVICE_PATH}
[Unit]
Description=Teradici CAM Idle Shutdown monitoring service
After=pcoip.service

[Service]
Type=simple
ExecStart=/usr/bin/python ${MONITOR_SCRIPT}
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
