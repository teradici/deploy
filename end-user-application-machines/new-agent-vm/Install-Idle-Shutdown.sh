#!/bin/bash
# Copyright 2017 Teradici Corporation

SERVICE="CAMIdleShutdown.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE}"
SERVICE_CONFIG_PATH="${SERVICE_PATH}.d"
SERVICE_CONFIG="${SERVICE_CONFIG_PATH}/CAMIdleShutdown.conf"
MONITOR_SCRIPT=/opt/Teradici_CAM_idle_shutdown.sh

function create_monitor_script() {
    touch ${MONITOR_SCRIPT}
    chmod +x ${MONITOR_SCRIPT}
    cat <<'EOF'> ${MONITOR_SCRIPT}
#!/bin/bash
# Copyright 2017 Teradici Corporation

# Shutdown the machine if it has been idle more than the specified number of minutes
# Additionally, do not log off if there is an active ssh connection, or
# there are instances of pcoip-server processes running.

## Global settings
##
# minimum number of minutes machine can be idle before shutting down
MIN_IDLE_WAIT_TIME=5

# maximum number of minutes machine can be idle before shutting down
MAX_IDLE_WAIT_TIME=10000 # about 7 days

# minimum number of minutes to wait between polling machine session status
MIN_POLL_INTERVAL=1

# maximum number of minutes to wait between polling machine session status
MAX_POLL_INTERVAL=60
##

####################################################################
# Log to Syslog
####################################################################
function logit {
   logger --id $$ -t "ShutdownIdleAgent" "$*"
}

####################################################################
# If there are active remote ssh connections or we detect PCoIP return 1, else 0
# Note that a remote ssh session is one where the remote address is NOT "0.0.0.0" (ipv4
# or "::0" or "::" (ipv6)
####################################################################
function activeConnectionsExist() {
    set -x

    # first, check to see if anyone is connected remotely
    #  last will produce something like the list below,

    #  someuser  pts/2         tervdiw10dev13.t Wed Jul 12 10:51   still logged in
    #  someuser  pts/1         0.0.0.0          Wed Jul 12 10:36   gone - no logout
    #  someuser  pts/0         0.0.0.0          Wed Jul 12 10:35   gone - no logout
    #  someuser  :100          0.0.0.0          Wed Jul 12 10:35   gone - no logout
    #  reboot   system reboot  0.0.0.0          Wed Jul 12 10:35   gone - no logout
    #  
    #  wtmp begins Wed Jul 12 10:35:17 2017

    # in this case, pts/2 has a remotely logged on user, but the rest are local ssh connections we
    # can ignore, including the system one.  Format is slightly different when the system status is displayed
        
    ipList=$(/usr/bin/last  | /usr/bin/grep 'still logged in' | /usr/bin/awk '{ if (!($0~"wtmp begins")) { if ($2 == "system") {print $4} else {print $3 }}}')

    for i in $ipList; do
        if [ $i != "0.0.0.0" ] && [ $i != "::" ] && [ $i != "::0" ]; then
            # a remote ssh connection detected
            echo 1
            return
        fi
    done

    # Is PCoIP active?
    /bin/ps -e | /bin/grep -s pcoip-server  > /dev/null 2>&1
    rc=$?

    if [ $rc -eq 0 ]; then
        # someone is connected via pcoip
        echo 1
        return
    fi

    echo 0
    return
}

####################################################################
# convert string to integer, 0 if it is invalid
####################################################################
function validateInt(){
    typeset -r input=$1
    if [[ $input =~ ^[0-9]+$ ]]; then
        echo $input
        return 
    fi
    echo 0
}

####################################################################
# Returns an integer representing the percentage cpuload of the busiest
# cpu.  e.g. 10 = 10%
# We do not attempt to normalize
####################################################################
function getCPULoad() {
    # get load average for last 15 minutes

    loadAvg=$(/usr/bin/uptime | sed s/"^.*load average:"// | sed s/","// | /usr/bin/awk '{ print $3}')
    result=$(echo "($loadAvg * 100 )" | bc)
    result=${result%%.*}
    if [ $result -gt 100 ]; then
        result=100
    fi
    echo $result
}

####################################################################
# Set the globals wait_minutes and poll_interval
####################################################################
function processArgs () {
    if [ $# -eq 3 ]; then
        wait_minutes=$(validateInt $1)
        poll_interval=$(validateInt $2)
        cpu_threshold=$(validateInt $3)
    elif [ $# -ne 0 ]; then
        echo "Usage $(basename $0): [ <wait-minutes> <poll-interval> <cpu-threshold> ]"
        echo "      where <wait-minutes> are the number of minutes a machine must be idle before it is shutdown"
        echo "      <poll-interval> are the number of minutes between checking for the idle state"
        echo "      and <cpu-threshold> the percentage cpu utilization below which a shutdown is allowed to occur"
        exit 1
    fi

    # clamp waiting minutes to max roughly 1 week, minimum of 5 minutes
    if [ $wait_minutes -gt $MAX_IDLE_WAIT_TIME ]; then
        wait_minutes=$MAX_IDLE_WAIT_TIME
        logit "Reset idle machine wait period to $wait_minutes minutes"
    elif [ $wait_minutes -lt $MIN_IDLE_WAIT_TIME ]; then
        wait_minutes=$MIN_IDLE_WAIT_TIME
        logit "Reset idle machine wait period to $wait_minutes minutes"
    fi

    if [ $poll_interval -gt $MAX_POLL_INTERVAL ]; then
        poll_interval=$MAX_POLL_INTERVAL
        logit "Reset polling interval to $poll_interval minutes"
    elif [ $poll_interval -lt $MIN_POLL_INTERVAL ]; then
        poll_interval=$MIN_POLL_INTERVAL
        logit "Reset polling interval to $poll_interval minutes"
    fi

    if [ $cpu_threshold -gt 100 ]; then
        cpu_threshold=100
        logit "Reset cpu threshold to $cpu_threshold"
    elif [ $cpu_threshold -lt 0 ]; then
        cpu_threshold=0
        logit "Reset cpu threshold to $cpu_threshold"
    fi
}

####################################################################
# Main program
# set the globals wait_minutes and poll_interval
####################################################################
function main() {
    wait_minutes=60  # default is an hour
    poll_interval=15 # default is 15 minutes
    cpu_threshold=20 # default 20%

    # this will potentially reset the above two variables
    processArgs $@
    
    required_idle_time=$(( 60 * $wait_minutes))

    if [ $(activeConnectionsExist) -gt 0 ]; then
        echo exit 0
    fi

    logit "Monitoring system for idle state every $poll_interval minutes and will shutdown machine if idle (every cpu < $cpu_threshold% utilization) for $wait_minutes minutes."

    startTime=0
    # Main while loop.  Flip between two states: someone is connected, and a triggered timer
    # counting until we shutdown or someone connects
    while [ 1 -ne 0 ]; do
        if [ $(activeConnectionsExist) -gt 0 ]; then
            startTime=0
        else
            if [ $startTime -eq 0 ]; then
                startTime=$(/bin/date +%s)
            fi

            cpuLoad=$(getCPULoad)
            if [ $cpuLoad -ge $cpu_threshold ]; then
                # a cpu load greater than threshold, assume something's going on
                #logit "Shutdown process reset because CPU load ($cpuLoad%) > $cpu_threshold%"
                startTime=0
            else
                currentTime=$(/bin/date +%s)
                elapsedIdleTime=$(( $currentTime - $startTime ))

                if [ $required_idle_time -le $elapsedIdleTime ]; then
                logit "Shutting down idle machine."
                sudo /sbin/shutdown now
                fi
            fi
        fi

        /bin/sleep $((60 * $poll_interval))
    done 

    exit 0
}

main $@
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
ExecStart=/usr/bin/sudo /usr/bin/bash ${MONITOR_SCRIPT} \${MinutesIdleBeforeShutdown} \${PollingIntervalMinutes} \${CPUUtilizationLimit}
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
