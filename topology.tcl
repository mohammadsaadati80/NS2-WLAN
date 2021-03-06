Mac/Simple set bandwidth_ 1.5Mb

#===================================
#        Functions Definition        
#===================================
proc Uni_Error {} {
    global error_rate
    set em_ [new ErrorModel]
    $em_ unit pkt
    $em_ set rate_ $error_rate
    $em_ ranvar [new RandomVariable/Uniform]
    return $em_
}
#===================================
#     Simulation parameters setup
#===================================
set val(chan)   Channel/WirelessChannel    ;# channel type
set val(prop)   Propagation/TwoRayGround   ;# radio-propagation model
set val(netif)  Phy/WirelessPhy            ;# network interface type
set val(mac)    Mac/802_11                 ;# MAC type
set val(ifq)    Queue/DropTail/PriQueue    ;# interface queue type
set val(ll)     LL                         ;# link layer type
set val(ant)    Antenna/OmniAntenna        ;# antenna model
set val(ifqlen) 50                         ;# max packet in ifq
set val(nn)     9                          ;# number of mobilenodes
set val(rp)     AODV                       ;# routing protocol
set val(x)      803                      ;# X dimension of topography
set val(y)      813                      ;# Y dimension of topography
set val(stop)   100.0                         ;# time of simulation end
set error_rate 0.00001                   ;#error rate of sending
#===================================
#        Initialization        
#===================================
#Create a ns simulator
set ns [new Simulator]

#Setup topography object
set topo       [new Topography]
$topo load_flatgrid $val(x) $val(y)
create-god $val(nn)

#Open the NS trace file
set tracefile [open out.tr w]
$ns trace-all $tracefile

#Open the NAM trace file
set namfile [open out.nam w]
$ns namtrace-all $namfile
$ns namtrace-all-wireless $namfile $val(x) $val(y)
set chan [new $val(chan)];#Create wireless channel

#===================================
#     Mobile node parameter setup
#===================================
$ns node-config -adhocRouting  $val(rp) \
                -llType        $val(ll) \
                -macType       $val(mac) \
                -ifqType       $val(ifq) \
                -ifqLen        $val(ifqlen) \
                -antType       $val(ant) \
                -propType      $val(prop) \
                -phyType       $val(netif) \
                -channel       $chan \
                -topoInstance  $topo \
                -agentTrace    ON \
                -routerTrace   OFF \
                -macTrace      ON \
                -movementTrace OFF \
		        -IncomingErrProc Uni_Error \
                -OutgoingErrProc Uni_Error
 
#===================================
#        Nodes Definition        
#===================================
#Create 9 nodes
set n0 [$ns node]
$n0 set X_ 295
$n0 set Y_ 713
$n0 set Z_ 0.0
$ns initial_node_pos $n0 20
set n1 [$ns node]
$n1 set X_ 140
$n1 set Y_ 589
$n1 set Z_ 0.0
$ns initial_node_pos $n1 20
set n2 [$ns node]
$n2 set X_ 420
$n2 set Y_ 646
$n2 set Z_ 0.0
$ns initial_node_pos $n2 20
set n3 [$ns node]
$n3 set X_ 217
$n3 set Y_ 428
$n3 set Z_ 0.0
$ns initial_node_pos $n3 20
set n4 [$ns node]
$n4 set X_ 393
$n4 set Y_ 480
$n4 set Z_ 0.0
$ns initial_node_pos $n4 20
set n5 [$ns node]
$n5 set X_ 540
$n5 set Y_ 469
$n5 set Z_ 0.0
$ns initial_node_pos $n5 20
set n6 [$ns node]
$n6 set X_ 552
$n6 set Y_ 637
$n6 set Z_ 0.0
$ns initial_node_pos $n6 20
set n7 [$ns node]
$n7 set X_ 703
$n7 set Y_ 626
$n7 set Z_ 0.0
$ns initial_node_pos $n7 20
set n8 [$ns node]
$n8 set X_ 695
$n8 set Y_ 461
$n8 set Z_ 0.0
$ns initial_node_pos $n8 20


#==============================================
#      Agents and Applications Definition        
#==============================================
#Setup a CBR Application over UDP connection
set udp0 [new Agent/UDP]
set cbr0 [new Application/Traffic/CBR]
set null [new Agent/Null]
$ns attach-agent $n0 $udp0
$ns attach-agent $n8 $null
$ns connect $udp0 $null
$cbr0 attach-agent $udp0
$cbr0 set packetSize_ 100Kb
$cbr0 set rate_ 1.0Mb
$cbr0 set random_ null
$ns at 1.0 "$cbr0 start"
$ns at 40.0 "$cbr0 stop"

#Setup a CBR Application over UDP connection
set udp3 [new Agent/UDP]
set cbr1 [new Application/Traffic/CBR]
set null1 [new Agent/Null]
$ns attach-agent $n7 $null1
$ns attach-agent $n3 $udp3
$ns connect $udp3 $null1
$cbr1 attach-agent $udp3
$cbr1 set packetSize_ 80Kb
$cbr1 set rate_ 1.0Mb
$cbr1 set random_ null
$ns at 30.0 "$cbr1 start"
$ns at 100.0 "$cbr1 stop"


#===================================
#        Termination        
#===================================
#Define a 'finish' procedure
proc finish {} {
    global ns tracefile namfile
    $ns flush-trace
    close $tracefile
    close $namfile
    exec nam out.nam &
    exit 0
}
for {set i 0} {$i < $val(nn) } { incr i } {
    $ns at $val(stop) "\$n$i reset"
}
$ns at $val(stop) "$ns nam-end-wireless $val(stop)"
$ns at $val(stop) "finish"
$ns at $val(stop) "puts \"done\" ; $ns halt"
$ns run
