/*
 * QEMU PCIe device for communication with HDL simulation.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "sysemu/kvm.h"
#include "migration/migration.h"
#include "qemu/error-report.h"
#include "qom/object_interfaces.h"
#include "qapi/visitor.h"
#include "net/net.h"
#include "acc/acc.h"


#define ACCELERATOR_EPRINTF(fmt, ...)                                          \
    do {                                                                       \
        fprintf(stderr, "ACCELERATOR: " fmt, ##__VA_ARGS__);                   \
    } while (0)
#if 0
#define ACCELERATOR_DPRINTF(fmt, ...)										   \
    do {                                                                       \
        fprintf(stderr, "ACCELERATOR: " fmt, ##__VA_ARGS__);                   \
    } while (0)
#else
#define ACCELERATOR_DPRINTF(fmt, ...)
#endif
typedef struct ACCPCIeState {
    PCIDevice parent_obj;

    /* BARs */
    MemoryRegion bar0;
    MemoryRegion bar1;

    /* NIC */
    NICState *nic;
    NICConf conf;

    /* QEMU-HDL Communication Channels */
    zsock_t *qemu_req;
    zsock_t *qemu_resp;
    zsock_t *hdl_req;
    zsock_t *hdl_resp;
    zsock_t *nic_req;
    zsock_t *nic_resp;
} ACCPCIeState;

#define TYPE_ACC_PCIE "accelerator-pcie"
#define ACC_PCIE(obj) OBJECT_CHECK(ACCPCIeState, (obj), TYPE_ACC_PCIE)


/*
Callback for write operation on BAR0. This is where data is sent from QEMU to
HDL over ZMQ sockets. When creating a new BAR with MMIO it is important that
this callback is implemented for that BAR (address translation is done on HDL
side, hence the correct offsets need to be added.)
*/
#define MMIO_WRITE_BAR(_num)                                                   \
    static void mmio_write_bar##_num(void *opaque, hwaddr addr, uint64_t val,  \
                                     unsigned size) {                          \
        ACCPCIeState *s = opaque;                                              \
        ACCData acc_req;                                                       \
        /*memset(&acc_req, 0, sizeof(ACCData));*/                              \
        /*Important to add offset for the BAR as address translation is done   \
         * on HDL side */                                                      \
        acc_req.address = (uint64_t)(addr) + BAR_OFFSET_BAR##_num;             \
        memcpy(&acc_req.data, &val, sizeof(uint64_t));                         \
        acc_req.op = WRITE;                                                    \
        acc_req.data_size = size;                                              \
        /*Create frame containing data to send */                              \
        zframe_t *frame = zframe_new(&acc_req, sizeof(ACCData));               \
        if (!frame) {                                                          \
            ACCELERATOR_EPRINTF("BAR[%d] WR ERROR %s:%d\n", _num, __func__,    \
                                __LINE__);                                     \
        }                                                                      \
        /* Send frame:                                                         \
           ZMQ write is non-blocking while the library's underlying queue is   \
           not full. when it is, send is blocking.                             \
        */                                                                     \
        int rv = zframe_send(&frame, s->qemu_req, 0);                          \
        if (rv != 0) {                                                         \
            ACCELERATOR_EPRINTF("BAR[%d] WR ERROR %s:%d\n", _num, __func__,    \
                                __LINE__);                                     \
        }                                                                      \
        /* Wait for response */                                                \
        frame = zframe_recv(s->qemu_resp);                                     \
        if (!frame) {                                                          \
            ACCELERATOR_EPRINTF("BAR[%d] WR ERROR %s:%d\n", _num, __func__,    \
                                __LINE__);                                     \
        }                                                                      \
    }

MMIO_WRITE_BAR(0)

/*
Callback for read operation on BAR0. This is a blocking read. QEMU will "hang"
while HDL services the read request. It will return when HDL has responded with
data over socket. There is no timeout and this can cause the program to hang
indefinitely.
*/
#define MMIO_READ_BAR(_num)                                                    \
    static uint64_t mmio_read_bar##_num(void *opaque, hwaddr addr,             \
                                        unsigned size) {                       \
        ACCPCIeState *s = opaque;                                              \
        ACCData acc_req;                                                       \
        /*memset(&acc_req, 0, sizeof(ACCData));*/                              \
        /* Setup request fields                                                \
           Important to add offset for the BAR as address translation is done  \
           on HDL side                                                         \
        */                                                                     \
        acc_req.address = (uint64_t)(addr) + BAR_OFFSET_BAR##_num;             \
        acc_req.op = READ;                                                     \
        acc_req.data_size = size;                                              \
        /* Create frame containing data to send */                             \
        zframe_t *frame = zframe_new(&acc_req, sizeof(ACCData));               \
        if (!frame) {                                                          \
            ACCELERATOR_EPRINTF("BAR[%d] RD ERROR %s:%d\n", _num, __func__,    \
                                __LINE__);                                     \
        }                                                                      \
        /* Send frame */                                                       \
        int rv = zframe_send(&frame, s->qemu_req, 0);                          \
        if (rv != 0) {                                                         \
            ACCELERATOR_EPRINTF("BAR[%d] RD ERROR %s:%d\n", _num, __func__,    \
                                __LINE__);                                     \
        }                                                                      \
        /* Wait for response */                                                \
        frame = zframe_recv(s->qemu_resp);                                     \
        if (!frame) {                                                          \
            ACCELERATOR_EPRINTF("BAR[%d] RD ERROR %s:%d\n", _num, __func__,    \
                                __LINE__);                                     \
        }                                                                      \
        ACCData *acc_data = (ACCData *)zframe_data(frame);                     \
        uint64_t data = 0;													   \
		switch(size) {														   \
			case 1:															   \
				data = *(uint8_t*)acc_data->data;                              \
				break;														   \
			case 2:															   \
				data = *(uint16_t*)acc_data->data;                             \
				break;														   \
			case 4:															   \
				data = *(uint32_t*)acc_data->data;                             \
				break;														   \
			case 8:															   \
				data = *(uint64_t*)acc_data->data;                             \
				break;														   \
			default:														   \
				ACCELERATOR_EPRINTF("BAR[%d] Unsupported read size %u\n",     \
															  _num, size);     \
		}																	   \
		ACCELERATOR_DPRINTF("BAR[%d] RD %016lx:   %lx\n", _num, addr, data);   \
        zframe_destroy(&frame);                                                \
        return data;                                                           \
    }

MMIO_READ_BAR(0)

/*
Callback called when there is activity on the HDL request socket. This callback
will handle the request made by HDL and respond appropriately. Since address
translation is done on HDL side, no need for it on QEMU.
*/
static void handle_hdl_request(void *opaque) {
    // ACCELERATOR_DPRINTF("in %s:%d\n", __func__, __LINE__);
    ACCPCIeState *s = opaque;
    PCIDevice *dev = PCI_DEVICE(s);
    // Poller so that no hdl packets are missed
    zpoller_t *poller = zpoller_new(s->hdl_req, NULL);
    if (!poller) {
        ACCELERATOR_EPRINTF("HDL REQ ERROR %s:%d\n", __func__, __LINE__);
    }
    while (1) {
        zsock_t *which = (zsock_t *)zpoller_wait(poller, 0);
        int terminate = zpoller_expired(poller) || zpoller_terminated(poller) ||
                        which != s->hdl_req;

        if (terminate) {
            zpoller_destroy(&poller);
            return;
        }

        zframe_t *frame = zframe_recv(s->hdl_req);
        if (!frame) {
            ACCELERATOR_EPRINTF("HDL REQ ERROR %s:%d\n", __func__, __LINE__);
        }
        ACCData *acc_data = (ACCData *)zframe_data(frame);

        ACCOp req = acc_data->op;
        uint64_t addr = acc_data->address;
        switch (req) {
        case READ:
            ACCELERATOR_DPRINTF("Host read request\n");
            cpu_physical_memory_read(addr, acc_data->data, acc_data->data_size);
            // Send frame
            int rv = zframe_send(&frame, s->hdl_resp, ZFRAME_REUSE);
            if (rv != 0) {
                ACCELERATOR_EPRINTF("HDL REQ ERROR %s:%d\n", __func__,
                                    __LINE__);
            }
            break;
        case WRITE:
            ACCELERATOR_DPRINTF("Host write request\n");
            cpu_physical_memory_write(addr, acc_data->data,
                                      acc_data->data_size);
            break;
        case INTR:
            ACCELERATOR_DPRINTF("Host intr request\n");
            msi_notify(dev, acc_data->vector);
            break;
        case NOOP:
        default:
            break;
        }
        zframe_destroy(&frame);
    }
}

/*
MMIO options for BAR region
*/
#define MEM_REGION_OPS_BAR(_num)                                               \
    static const MemoryRegionOps mmio_ops_bar##_num = {                        \
        .read = mmio_read_bar##_num,                                           \
        .write = mmio_write_bar##_num,                                         \
        .endianness = DEVICE_NATIVE_ENDIAN,                                    \
        .valid =                                                               \
            {                                                                  \
                .min_access_size = 1, .max_access_size = 8,                    \
            },                                                                 \
        .impl =                                                                \
            {                                                                  \
                .min_access_size = 1, .max_access_size = 8,                    \
            },                                                                 \
    };

MEM_REGION_OPS_BAR(0)

// NIC Features
// Transmit processed packet recieved from HDL
static void net_tx_packet(void *opaque) {
    ACCPCIeState *s = opaque;
    ACCELERATOR_DPRINTF("in %s:%d\n", __func__, __LINE__);
    zpoller_t *poller = zpoller_new(s->nic_resp, NULL);
    assert(poller);
    //ZMQ doesn't write until the last send (i.e all the partial messages are here)
    while (1) {
        zsock_t *which = (zsock_t *)zpoller_wait(poller, 0);
        int terminate = zpoller_expired(poller) || zpoller_terminated(poller) ||
                        which != s->nic_resp;
        if (terminate) {
            zpoller_destroy(&poller);
            return;
        }
        // ACCELERATOR_DPRINTF("NIC: recieved packet from hdl\n");
        // ACCELERATOR_DPRINTF("in %s:%d\n", __func__, __LINE__);
        zframe_t *frame = zframe_recv(s->nic_resp);
        assert(frame);
        ACCNICData *acc_data = (ACCNICData *)zframe_data(frame);        
        ACCELERATOR_DPRINTF("NIC: Sending packet to world\n");
        qemu_send_packet(qemu_get_queue(s->nic), acc_data->data, acc_data->size);
        zframe_destroy(&frame);
    }
}

// Recieve packet from OS and send to HDL NIC
static ssize_t net_rx_packet(NetClientState *nc, const uint8_t *buf,
                             size_t size) {
    ACCELERATOR_DPRINTF("in %s:%d\n", __func__, __LINE__);
    ACCPCIeState *s = qemu_get_nic_opaque(nc);
    ACCNICData acc_req;
    //memset(&acc_req, 0, sizeof(ACCNICData));
    acc_req.size = size;
    acc_req.id = 1;
    memcpy(acc_req.data, buf, size);
    // Create frame containing data to send
    zframe_t *frame = zframe_new(&acc_req, sizeof(ACCNICData));
    assert(frame);
    // Send frame
    int rv = zframe_send(&frame, s->nic_req, 0);
    assert(rv == 0);
    ACCELERATOR_DPRINTF("NIC: sent packet to hdl\n");
    return size;
}

// NIC Info
static NetClientInfo net_acc_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(ACCPCIeState),
    .receive = net_rx_packet
};

static void acc_pcie_realize(PCIDevice *dev, Error **errp) {

    ACCPCIeState *s = ACC_PCIE(dev);
    DeviceState *d = DEVICE(dev);
    
    uint8_t *pci_conf;
    pci_conf = dev->config;
    pci_conf[PCI_COMMAND] = PCI_COMMAND_IO | PCI_COMMAND_MEMORY;

    // Initialize BAR regions
    memory_region_init_io(&s->bar0, OBJECT(s), &mmio_ops_bar0, s, "bar0-mmio",
                          (uint64_t)REGION_SIZE_BAR0);

    // Register BAR regions
    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar0);
    // PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_PREFETCH | PCI_BASE_ADDRESS_MEM_TYPE_64;

    // Open ZeroMQ connections to HDL
    int port = atoi(getenv("COSIM_PORT"));
    //initialize 0mq sockets
    char buffer[50];
    // request from qemu
    memset(buffer, 0, 50);
    sprintf(buffer, SOCK_BASE, SEND_SOCK, port);
    s->qemu_req = zsock_new_push(buffer);
    // hdl response to request
    memset(buffer, 0, 50);
    sprintf(buffer, SOCK_BASE, RECV_SOCK, port + 1);
    s->qemu_resp = zsock_new_pull(buffer);
    // request from hdl
    memset(buffer, 0, 50);
    sprintf(buffer, SOCK_BASE, RECV_SOCK, port + 2);
    s->hdl_req = zsock_new_pull(buffer);
    // qemu response to request
    memset(buffer, 0, 50);
    sprintf(buffer, SOCK_BASE, SEND_SOCK, port + 3);
    s->hdl_resp = zsock_new_push(buffer);
    // nic request
    memset(buffer, 0, 50);
    sprintf(buffer, SOCK_BASE, SEND_SOCK, port + 4);
    s->nic_req = zsock_new_push(buffer);
    // nic response
    memset(buffer, 0, 50);
    sprintf(buffer, SOCK_BASE, RECV_SOCK, port + 5);
    s->nic_resp = zsock_new_pull(buffer);
    assert(s->qemu_req && s->qemu_resp);
    assert(s->hdl_req && s->hdl_resp);
    assert(s->nic_req && s->nic_resp);

    // Listen for requests from HDL (register zsock fd with QEMU)
    size_t opt_len = sizeof(int *);
    int hdl_fd, nic_fd;
    void *zmq_sock = zsock_resolve(s->hdl_req);
    int rv = zmq_getsockopt(zmq_sock, ZMQ_FD, &hdl_fd, &opt_len);
    assert(rv == 0);
    qemu_set_fd_handler(hdl_fd, handle_hdl_request, NULL, s);
    zmq_sock = zsock_resolve(s->nic_resp);
    rv = zmq_getsockopt(zmq_sock, ZMQ_FD, &nic_fd, &opt_len);
    assert(rv == 0);
    qemu_set_fd_handler(nic_fd, net_tx_packet, NULL, s);

    // NIC init
    s->nic = qemu_new_nic(&net_acc_info, &s->conf,
                          object_get_typename(OBJECT(dev)), d->id, s);
    qemu_format_nic_info_str(qemu_get_queue(s->nic), s->conf.macaddr.a);
    
    // MSI init
    msi_init(dev, 0x00, NUM_MSI_VEC, false, false, errp);
}

/* TODO Is this needed? */
static void acc_pcie_exit(PCIDevice *dev) {
    ACCPCIeState *s = ACC_PCIE(dev);
    zsock_destroy(&s->hdl_req);
    zsock_destroy(&s->hdl_resp);
    zsock_destroy(&s->qemu_req);
    zsock_destroy(&s->qemu_resp);
    zsock_destroy(&s->nic_req);
    zsock_destroy(&s->nic_resp);
    zsock_destroy(&ls_sock);
}
static void acc_pcie_reset(DeviceState *ds) { /*TODO*/
}

static Property acc_pcie_properties[] = {
    DEFINE_NIC_PROPERTIES(ACCPCIeState, conf), 
    DEFINE_PROP_END_OF_LIST(),
};

static void acc_pcie_class_init(ObjectClass *klass, void *data) {
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = acc_pcie_realize;
    k->exit = acc_pcie_exit;
    k->vendor_id = ACC_VENDOR_ID;
    k->device_id = ACC_DEVICE_ID;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    k->revision = 1;

    dc->reset = acc_pcie_reset;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->props = acc_pcie_properties;
    dc->desc = "PCIe HDL-VM Data Transfer with NIC Support";
}

static const TypeInfo acc_pcie_info = {
    .name = TYPE_ACC_PCIE,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(ACCPCIeState),
    .class_init = acc_pcie_class_init
};

static void acc_pcie_register_types(void) {
    type_register_static(&acc_pcie_info);
}

type_init(acc_pcie_register_types);
