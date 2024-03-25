/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> l4_port_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_DECAY_UPDATE = 16w0x8888;

typedef bit<8> ip_proto_t;
const ip_proto_t IP_PROTO_ICMP = 1;
const ip_proto_t IP_PROTO_TCP = 6;
const ip_proto_t IP_PROTO_UDP = 17;

typedef bit<32> count_t;
typedef bit<32> window_t;

const bit<3> HH_DIGEST = 0x03;
struct hh_digest_t {
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
    bit<8>  protocol;
    l4_port_t src_port;
    l4_port_t dst_port;
}

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    ether_type_t ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    ip_proto_t   protocol;
    bit<16>  hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
}

header tcp_h {
    l4_port_t src_port;
    l4_port_t dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flag;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    l4_port_t src_port;
    l4_port_t dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h  ipv4;
    tcp_h   tcp;
    udp_h   udp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    l4_port_t src_port;
    l4_port_t dst_port;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.src_port = 0;
        meta.dst_port = 0;
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP    : parse_tcp;
            IP_PROTO_UDP    : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.src_port = hdr.tcp.src_port;
        meta.dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.src_port = hdr.udp.src_port;
        meta.dst_port = hdr.udp.dst_port;
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    bit<32> ts_0;
    bit<32> ts_1;
    bit<32> ts_2;
    bit<1> hh = 0;
    bit<16>     index0 = 0;
    bit<16>     index1 = 0;
    bit<8>     index2 = 0;
    count_t     count_r0 = 0;
    count_t     count_r1 = 0;
    count_t     count_r2 = 0;

    count_t     count0 = 0;
    window_t    diff_0 = 0;
    count_t     count1 = 0;
    window_t    diff_1 = 0;
    count_t     count2 = 0;
    window_t    diff_2 = 0;

    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_index0;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_index1;
    Hash<bit<8>>(HashAlgorithm_t.CRC16) hash_index2;

    Register<count_t,_>(65536) sketch0;
    Register<window_t,_>(65536) window0;
    Register<count_t,_>(65536) sketch1;
    Register<window_t,_>(65536) window1;
    Register<count_t,_>(256) sketch2;
    Register<window_t,_>(256) window2;

    RegisterAction<count_t, _, count_t> (sketch0) sketch0_count = {
        void apply(inout count_t val, out count_t rv) {
            val = val |+| 1;
            rv = val;
        }
    };
    
    RegisterAction<window_t, _, window_t> (window0) window0_diff = {
        void apply(inout window_t val, out window_t x) {
            x = ts_0 - val;
        }
    };    

    RegisterAction<count_t, _, count_t> (sketch1) sketch1_count = {
        void apply(inout count_t val, out count_t rv) {
            val = val |+| 1;
            rv = val;
        }
    };

    RegisterAction<window_t, _, window_t> (window1) window1_diff = {
        void apply(inout window_t val, out window_t y) {
            y = ts_1 - val;
        }
    };    

    RegisterAction<count_t, _, count_t> (sketch2) sketch2_count = {
        void apply(inout count_t val, out count_t rv) {
            val = val |+| 1;
            rv = val;
        }
    };
    
    RegisterAction<window_t, _, window_t> (window2) window2_diff = {
        void apply(inout window_t val, out window_t z) {
            z = ts_2 - val;
        }
    };    

    action drop() {
        ig_dprsr_md.drop_ctl = 0x0;    // drop packet
        exit;
    }

    action forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table ipv4_forward {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        default_action = NoAction();
        size = 64;
    }

    action generate_digest() {
        ig_dprsr_md.digest_type = HH_DIGEST;
    }

    action count_1() {
        count1 = sketch1_count.execute(index1);
    }
        
    action count_2() {
        count2 = sketch2_count.execute(index2);
    }
    
    action diff_window1() {
        diff_1 = window1_diff.execute(index0);
    }
    
    action diff_window2() {
        diff_2 = window2_diff.execute(index0);
    }    
    
    
    

    apply {
        ipv4_forward.apply();
        index0 = hash_index0.get(
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                meta.src_port,
                meta.dst_port
            }
        );

        index1 = hash_index1.get(
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                meta.src_port,
                meta.dst_port
            }
        );

        index2 = hash_index2.get(
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                meta.src_port,
                meta.dst_port
            }
        );
                
   
        count0 = sketch0_count.execute(index0);
        diff_0 = window0_diff.execute(index0);
   
        if (diff_0 > 0) {
            count_1();
            diff_window1();
        } else {
            generate_digest();         
        }       
        
        
        if (diff_0 < 0) {
            NoAction();
        }
        else if (diff_1 > 0) {
            count_2();
            diff_window2();       
        } 
        else {
            generate_digest();        
        }  


        if (diff_0 < 0) {
            NoAction();
        }
        else if (diff_1 < 0) {
            NoAction();
        }        
        else if (diff_2 > 0) {
            NoAction();        
        }
        else {
            generate_digest();        
        }  
        


        // we do not need egress processing for now
        ig_tm_md.bypass_egress = 1;
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Digest <hh_digest_t>() hh_digest;

    apply {
        if(ig_dprsr_md.digest_type == HH_DIGEST) {
            hh_digest.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, meta.src_port, meta.dst_port});
        }

        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
