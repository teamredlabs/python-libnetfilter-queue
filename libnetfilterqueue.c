#include <Python.h>
#include <structmember.h>

#include <string.h>
#include <sys/time.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// START: NetfilterQueueData

typedef struct {
    PyObject_HEAD
    struct nfq_data* data;
    PyIntObject* verdict;
    PyIntObject* mark;
} NetfilterQueueData;

static PyObject* NetfilterQueueData_new (PyTypeObject* type, PyTupleObject* args) {
    NetfilterQueueData* self;
    self = (NetfilterQueueData*) type->tp_alloc(type, 0);
    self->data = NULL;
    self->verdict = NULL;
    self->mark = NULL;
    return (PyObject*) self;
}

static int NetfilterQueueData_init (NetfilterQueueData* self, PyTupleObject* args) {
    return 0;
}

static void NetfilterQueueData_dealloc (NetfilterQueueData* self) {
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject* NetfilterQueueData_get_packet_hw (NetfilterQueueData* self) {
    struct nfqnl_msg_packet_hw* msg_packet_hw = nfq_get_packet_hw(self->data);
    return PyString_FromStringAndSize((char*) msg_packet_hw->hw_addr, 8);
}

static PyObject* NetfilterQueueData_get_nfmark (NetfilterQueueData* self) {
    return PyInt_FromLong((long) nfq_get_nfmark(self->data));
}

static PyObject* NetfilterQueueData_get_timestamp (NetfilterQueueData* self) {
    PyLongObject* tv_sec_object;
    PyLongObject* tv_usec_object;
    PyTupleObject* tv_object;
    struct timeval tv;
    if (nfq_get_timestamp(self->data, &tv)) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_get_timestamp failed");
        return NULL;
    }
    tv_sec_object = (PyLongObject*) PyLong_FromLong((long) tv.tv_sec);
    tv_usec_object = (PyLongObject*) PyLong_FromLong((long) tv.tv_usec);
    tv_object = (PyTupleObject*) PyTuple_Pack(2, tv_sec_object, tv_usec_object);
    Py_DECREF(tv_sec_object);
    Py_DECREF(tv_usec_object);
    return (PyObject*) tv_object;
}

static PyObject* NetfilterQueueData_get_indev (NetfilterQueueData* self) {
    return PyInt_FromLong((long) nfq_get_indev(self->data));
}

static PyObject* NetfilterQueueData_get_physindev (NetfilterQueueData* self) {
    return PyInt_FromLong((long) nfq_get_physindev(self->data));
}

static PyObject* NetfilterQueueData_get_outdev (NetfilterQueueData* self) {
    return PyInt_FromLong((long) nfq_get_outdev(self->data));
}

static PyObject* NetfilterQueueData_get_physoutdev (NetfilterQueueData* self) {
    return PyInt_FromLong((long) nfq_get_physoutdev(self->data));
}

static PyObject* NetfilterQueueData_get_payload (NetfilterQueueData* self) {
    int length;
    char* data;
    length = nfq_get_payload(self->data, &data);
    if (length < 0) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_get_payload failed");
        return NULL;
    }
    return PyString_FromStringAndSize(data, length);
}

static PyObject* NetfilterQueueData_get_uid (NetfilterQueueData* self) {
    uint32_t uid;
    if (nfq_get_uid(self->data, &uid)) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_get_uid failed");
        return NULL;
    }
    return PyInt_FromLong((long) uid);
}

static PyObject* NetfilterQueueData_get_gid (NetfilterQueueData* self) {
    uint32_t gid;
    if (nfq_get_gid(self->data, &gid)) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_get_gid failed");
        return NULL;
    }
    return PyInt_FromLong((long) gid);
}

static PyObject* NetfilterQueueData_set_verdict (NetfilterQueueData* self, PyTupleObject* args, PyDictObject* kwargs) {
    static char* kwlist[] = {"verdict", "mark", NULL};
    PyObject* verdict;
    PyObject* mark = Py_None;
    if (!PyArg_ParseTupleAndKeywords((PyObject*) args, (PyObject*) kwargs, "N|N", kwlist, &verdict, &mark)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint32_t verdict, uint32_t mask)");
        return NULL;
    }
    if (PyInt_Check(verdict)) {
        switch ((uint32_t) PyInt_AsUnsignedLongMask(verdict)) {
            case NF_DROP:
            case NF_ACCEPT:
            case NF_STOLEN:
            case NF_QUEUE:
            case NF_REPEAT:
            case NF_STOP:
                self->verdict = verdict;
                Py_INCREF(verdict);
                if (PyInt_Check(mark)) {
                    self->mark = mark;
                    Py_INCREF(mark);
                }
                Py_RETURN_NONE;
        }
    }
    PyErr_SetString(PyExc_ValueError, "Parameters must be either NF_DROP, NF_ACCEPT, NF_STOLEN, NF_QUEUE, NF_REPEAT, NF_STOP");
    return NULL;
}

static PyMemberDef NetfilterQueueData_members[] = {
    {NULL}
};

static PyMethodDef NetfilterQueueData_methods[] = {
    {"get_packet_hw", (PyCFunction) NetfilterQueueData_get_packet_hw, METH_NOARGS, NULL},
    {"get_nfmark", (PyCFunction) NetfilterQueueData_get_nfmark, METH_NOARGS, NULL},
    {"get_timestamp", (PyCFunction) NetfilterQueueData_get_timestamp, METH_NOARGS, NULL},
    {"get_indev", (PyCFunction) NetfilterQueueData_get_indev, METH_NOARGS, NULL},
    {"get_physindev", (PyCFunction) NetfilterQueueData_get_physindev, METH_NOARGS, NULL},
    {"get_outdev", (PyCFunction) NetfilterQueueData_get_outdev, METH_NOARGS, NULL},
    {"get_physoutdev", (PyCFunction) NetfilterQueueData_get_physoutdev, METH_NOARGS, NULL},
    {"get_payload", (PyCFunction) NetfilterQueueData_get_payload, METH_NOARGS, NULL},
    {"get_uid", (PyCFunction) NetfilterQueueData_get_uid, METH_NOARGS, NULL},
    {"get_gid", (PyCFunction) NetfilterQueueData_get_gid, METH_NOARGS, NULL},
    {"set_verdict", (PyCFunction) NetfilterQueueData_set_verdict, METH_VARARGS | METH_KEYWORDS, NULL},
    {NULL}
};

static PyTypeObject NetfilterQueueDataType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "libnetfilterqueue.NetfilterQueueData",   /* tp_name */
    sizeof(NetfilterQueueData),               /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor) NetfilterQueueData_dealloc,  /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "Wrapper for (struct nfq_data *)",        /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    NetfilterQueueData_methods,               /* tp_methods */
    NetfilterQueueData_members,               /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc) NetfilterQueueData_init,       /* tp_init */
    0,                                        /* tp_alloc */
    (newfunc) NetfilterQueueData_new,         /* tp_new */
};

// END: NetfilterQueueData

// BEGIN: NetfilterQueueQueueHandle

typedef struct {
    PyObject_HEAD
    struct nfq_q_handle* queue;
    PyObject* callback;
} NetfilterQueueQueueHandle;

static PyObject* NetfilterQueueQueueHandle_new (PyTypeObject* type, PyTupleObject* args) {
    NetfilterQueueQueueHandle* self;
    self = (NetfilterQueueQueueHandle*) type->tp_alloc(type, 0);
    self->queue = NULL;
    self->callback = NULL;
    return (PyObject*) self;
}

static int NetfilterQueueQueueHandle_init (NetfilterQueueQueueHandle* self, PyTupleObject* args) {
    return 0;
}

static void NetfilterQueueQueueHandle_dealloc (NetfilterQueueQueueHandle* self) {
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static int NetfilterQueueQueueHandle_callback (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    PyObject* args;
    NetfilterQueueQueueHandle* self;
    NetfilterQueueData* data_object;
    struct nfqnl_msg_packet_hdr* packet_header;
    uint32_t packet_id;
    uint32_t verdict;
    uint32_t mark;

    self = (NetfilterQueueQueueHandle*) data;

    if (self->callback) {
        args = PyTuple_New(0);
        data_object = (NetfilterQueueData*) PyObject_CallObject((PyObject*) &NetfilterQueueDataType, args);
        Py_DECREF(args);

        data_object->data = nfa;
        args = PyTuple_Pack(1, data_object);
        PyObject_CallObject(self->callback, args);
        Py_DECREF(args);

        if (data_object->verdict) {
            verdict = PyInt_AsUnsignedLongMask(data_object->verdict);
            Py_DECREF(data_object->verdict);
            data_object->verdict = NULL;

            packet_header = nfq_get_msg_packet_hdr(nfa);
            packet_id = ntohl(packet_header->packet_id);

            if (data_object->mark) {
                mark = PyInt_AsUnsignedLongMask(data_object->mark);
                Py_DECREF(data_object->mark);
                data_object->mark = NULL;

                nfq_set_verdict_mark(self->queue, packet_id, verdict, mark, 0, NULL);
                Py_DECREF(data_object);
                return 0;
            }

            nfq_set_verdict(self->queue, packet_id, verdict, 0, NULL);
            Py_DECREF(data_object);
            return 0;
        }
        Py_DECREF(data_object);
        return 0;
    }
    return 0;
}

static PyObject* NetfilterQueueQueueHandle_set_mode (NetfilterQueueQueueHandle* self, PyTupleObject* args) {
    uint8_t mode;
    uint32_t range;
    if (!PyArg_ParseTuple((PyObject*) args, "bI", &mode, &range)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint8_t mode, uint32_t range)");
        return NULL;
    }
    if (nfq_set_mode(self->queue, mode, range)) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_set_mode failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterQueueQueueHandle_set_flags (NetfilterQueueQueueHandle* self, PyTupleObject* args) {
    uint32_t mask;
    uint32_t flags;
    if (!PyArg_ParseTuple((PyObject*) args, "II", &mask, &flags)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint32_t mask, uint32_t flags)");
        return NULL;
    }
    if (nfq_set_queue_flags(self->queue, mask, flags)) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_set_queue_flags failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterQueueQueueHandle_set_maxlen (NetfilterQueueQueueHandle* self, PyTupleObject* args) {
    uint32_t queuelen;
    if (!PyArg_ParseTuple((PyObject*) args, "I", &queuelen)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint32_t queuelen)");
        return NULL;
    }
    if (nfq_set_queue_maxlen(self->queue, queuelen)) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_set_queue_maxlen failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterQueueQueueHandle_destroy (NetfilterQueueQueueHandle* self) {
    if (self->queue == NULL) {
        PyErr_SetString(PyExc_ValueError, "Queue handle pointer not initialized");
        return NULL;
    }
    if (nfq_destroy_queue(self->queue)) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_destroy_queue failed");
        return NULL;
    }
    self->queue = NULL;
    if (self->callback) {
        Py_DECREF(self->callback);
        self->callback = NULL;
    }
    Py_RETURN_NONE;
}

static PyMemberDef NetfilterQueueQueueHandle_members[] = {
    {NULL}
};

static PyMethodDef NetfilterQueueQueueHandle_methods[] = {
    {"set_mode", (PyCFunction) NetfilterQueueQueueHandle_set_mode, METH_VARARGS, NULL},
    {"set_flags", (PyCFunction) NetfilterQueueQueueHandle_set_flags, METH_VARARGS, NULL},
    {"set_maxlen", (PyCFunction) NetfilterQueueQueueHandle_set_maxlen, METH_VARARGS, NULL},
    {"destroy", (PyCFunction) NetfilterQueueQueueHandle_destroy, METH_NOARGS, NULL},
    {NULL}
};

static PyTypeObject NetfilterQueueQueueHandleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "libnetfilterqueue.NetfilterQueueQueueHandle",  /* tp_name */
    sizeof(NetfilterQueueQueueHandle),              /* tp_basicsize */
    0,                                              /* tp_itemsize */
    (destructor) NetfilterQueueQueueHandle_dealloc, /* tp_dealloc */
    0,                                              /* tp_print */
    0,                                              /* tp_getattr */
    0,                                              /* tp_setattr */
    0,                                              /* tp_compare */
    0,                                              /* tp_repr */
    0,                                              /* tp_as_number */
    0,                                              /* tp_as_sequence */
    0,                                              /* tp_as_mapping */
    0,                                              /* tp_hash */
    0,                                              /* tp_call */
    0,                                              /* tp_str */
    0,                                              /* tp_getattro */
    0,                                              /* tp_setattro */
    0,                                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,       /* tp_flags */
    "Wrapper for (struct nfq_q_handle *)",          /* tp_doc */
    0,                                              /* tp_traverse */
    0,                                              /* tp_clear */
    0,                                              /* tp_richcompare */
    0,                                              /* tp_weaklistoffset */
    0,                                              /* tp_iter */
    0,                                              /* tp_iternext */
    NetfilterQueueQueueHandle_methods,              /* tp_methods */
    NetfilterQueueQueueHandle_members,              /* tp_members */
    0,                                              /* tp_getset */
    0,                                              /* tp_base */
    0,                                              /* tp_dict */
    0,                                              /* tp_descr_get */
    0,                                              /* tp_descr_set */
    0,                                              /* tp_dictoffset */
    (initproc) NetfilterQueueQueueHandle_init,      /* tp_init */
    0,                                              /* tp_alloc */
    (newfunc) NetfilterQueueQueueHandle_new,        /* tp_new */
};

// END: NetfilterQueueQueueHandle

// BEGIN: NetfilterQueueHandle

typedef struct {
    PyObject_HEAD
    struct nfq_handle* handle;
} NetfilterQueueHandle;

static PyObject* NetfilterQueueHandle_new (PyTypeObject* type, PyTupleObject* args) {
    NetfilterQueueHandle* self;
    self = (NetfilterQueueHandle*) type->tp_alloc(type, 0);
    self->handle = NULL;
    return (PyObject*) self;
}

static int NetfilterQueueHandle_init (NetfilterQueueHandle* self, PyTupleObject* args) {
    return 0;
}

static void NetfilterQueueHandle_dealloc (NetfilterQueueHandle* self) {
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject* NetfilterQueueHandle_bind_pf (NetfilterQueueHandle* self, PyTupleObject* args) {
    uint16_t pf;
    if (!PyArg_ParseTuple((PyObject*) args, "H", &pf)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint16_t pf)");
        return NULL;
    }
    if (nfq_bind_pf(self->handle, pf)) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_bind_pf failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterQueueHandle_unbind_pf (NetfilterQueueHandle* self, PyTupleObject* args) {
    uint16_t pf;
    if (!PyArg_ParseTuple((PyObject*) args, "H", &pf)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint16_t pf)");
        return NULL;
    }
    if (nfq_unbind_pf(self->handle, pf)) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_unbind_pf failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterQueueHandle_create_queue (NetfilterQueueHandle* self, PyTupleObject* args) {
    PyObject* empty;
    NetfilterQueueQueueHandle* queue_object;
    struct nfq_q_handle* queue_struct;
    uint16_t num;
    PyObject* callback;
    if (!PyArg_ParseTuple((PyObject*) args, "HN", &num, &callback)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint16_t num, function callback)");
        return NULL;
    }
    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint16_t num, function callback)");
        return NULL;
    }
    empty = PyTuple_New(0);
    queue_object = (NetfilterQueueQueueHandle*) PyObject_CallObject((PyObject*) &NetfilterQueueQueueHandleType, empty);
    Py_DECREF(empty);
    queue_object->callback = callback;
    Py_INCREF(callback);
    queue_struct = nfq_create_queue(self->handle, num, &NetfilterQueueQueueHandle_callback, queue_object);
    if (!queue_struct) {
        Py_DECREF(callback);
        queue_object->callback = NULL;
        Py_DECREF(queue_object);
        queue_object = NULL;
        PyErr_SetString(PyExc_OSError, "Call to nfq_create_queue failed");
        return NULL;
    }
    queue_object->queue = queue_struct;
    return (PyObject*) queue_object;
}

static PyObject* NetfilterQueueHandle_handle_packet (NetfilterQueueHandle* self, PyTupleObject* args) {
    char* data;
    int length;
    if (!PyArg_ParseTuple((PyObject*) args, "s#", &data, &length)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (char* data)");
        return NULL;
    }
    nfq_handle_packet(self->handle, data, length);
    Py_RETURN_NONE;
}

static PyObject* NetfilterQueueHandle_fd (NetfilterQueueHandle* self) {
    return PyInt_FromLong(nfq_fd(self->handle));
}

static PyObject* NetfilterQueueHandle_close (NetfilterQueueHandle* self) {
    if (nfq_close(self->handle)) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_close failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyMemberDef NetfilterQueueHandle_members[] = {
    {NULL}
};

static PyMethodDef NetfilterQueueHandle_methods[] = {
    {"bind_pf", (PyCFunction) NetfilterQueueHandle_bind_pf, METH_VARARGS, NULL},
    {"unbind_pf", (PyCFunction) NetfilterQueueHandle_unbind_pf, METH_VARARGS, NULL},
    {"create_queue", (PyCFunction) NetfilterQueueHandle_create_queue, METH_VARARGS, NULL},
    {"handle_packet", (PyCFunction) NetfilterQueueHandle_handle_packet, METH_VARARGS, NULL},
    {"fd", (PyCFunction) NetfilterQueueHandle_fd, METH_NOARGS, NULL},
    {"close", (PyCFunction) NetfilterQueueHandle_close, METH_NOARGS, NULL},
    {NULL}
};

static PyTypeObject NetfilterQueueHandleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "libnetfilterqueue.NetfilterQueueHandle",  /* tp_name */
    sizeof(NetfilterQueueHandle),              /* tp_basicsize */
    0,                                         /* tp_itemsize */
    (destructor) NetfilterQueueHandle_dealloc, /* tp_dealloc */
    0,                                         /* tp_print */
    0,                                         /* tp_getattr */
    0,                                         /* tp_setattr */
    0,                                         /* tp_compare */
    0,                                         /* tp_repr */
    0,                                         /* tp_as_number */
    0,                                         /* tp_as_sequence */
    0,                                         /* tp_as_mapping */
    0,                                         /* tp_hash */
    0,                                         /* tp_call */
    0,                                         /* tp_str */
    0,                                         /* tp_getattro */
    0,                                         /* tp_setattro */
    0,                                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,  /* tp_flags */
    "Wrapper for (struct nfq_handle *)",       /* tp_doc */
    0,                                         /* tp_traverse */
    0,                                         /* tp_clear */
    0,                                         /* tp_richcompare */
    0,                                         /* tp_weaklistoffset */
    0,                                         /* tp_iter */
    0,                                         /* tp_iternext */
    NetfilterQueueHandle_methods,              /* tp_methods */
    NetfilterQueueHandle_members,              /* tp_members */
    0,                                         /* tp_getset */
    0,                                         /* tp_base */
    0,                                         /* tp_dict */
    0,                                         /* tp_descr_get */
    0,                                         /* tp_descr_set */
    0,                                         /* tp_dictoffset */
    (initproc) NetfilterQueueHandle_init,      /* tp_init */
    0,                                         /* tp_alloc */
    (newfunc) NetfilterQueueHandle_new,        /* tp_new */
};

// END: NetfilterQueueHandle

static PyObject* libnetfilterqueue_open (PyObject *self) {
    PyObject* empty;
    NetfilterQueueHandle* handle_object;
    struct nfq_handle* handle_struct;
    handle_struct = nfq_open();
    if (!handle_struct) {
        PyErr_SetString(PyExc_OSError, "Call to nfq_open failed");
        return NULL;
    }
    empty = PyTuple_New(0);
    handle_object = (NetfilterQueueHandle*) PyObject_CallObject((PyObject*) &NetfilterQueueHandleType, empty);
    Py_DECREF(empty);
    handle_object->handle = handle_struct;
    return (PyObject*) handle_object;
}

static PyMethodDef libnetfilterqueue_methods[] = {
    {"open", (PyCFunction) libnetfilterqueue_open, METH_NOARGS, NULL},
    {NULL}
};

PyMODINIT_FUNC initlibnetfilterqueue (void) {
    PyObject* module;

    if (PyType_Ready(&NetfilterQueueDataType) < 0)
        return;
    if (PyType_Ready(&NetfilterQueueQueueHandleType) < 0)
        return;
    if (PyType_Ready(&NetfilterQueueHandleType) < 0)
        return;

    module = Py_InitModule("libnetfilterqueue", libnetfilterqueue_methods);
    if (module == NULL)
        return;

    Py_INCREF((PyObject*) &NetfilterQueueDataType);
    PyModule_AddObject(module, "NetfilterQueueData", (PyObject*) &NetfilterQueueDataType);

    Py_INCREF((PyObject*) &NetfilterQueueQueueHandleType);
    PyModule_AddObject(module, "NetfilterQueueQueueHandle", (PyObject*) &NetfilterQueueQueueHandleType);

    Py_INCREF((PyObject*) &NetfilterQueueHandleType);
    PyModule_AddObject(module, "NetfilterQueueHandle", (PyObject*) &NetfilterQueueHandleType);

    PyModule_AddIntConstant(module, "NFQNL_COPY_NONE", NFQNL_COPY_NONE);
    PyModule_AddIntConstant(module, "NFQNL_COPY_META", NFQNL_COPY_META);
    PyModule_AddIntConstant(module, "NFQNL_COPY_PACKET", NFQNL_COPY_PACKET);

    PyModule_AddIntConstant(module, "NFQA_CFG_F_FAIL_OPEN", NFQA_CFG_F_FAIL_OPEN);
    PyModule_AddIntConstant(module, "NFQA_CFG_F_CONNTRACK", NFQA_CFG_F_CONNTRACK);
    PyModule_AddIntConstant(module, "NFQA_CFG_F_GSO", NFQA_CFG_F_GSO);

    PyModule_AddIntConstant(module, "NF_DROP", NF_DROP);
    PyModule_AddIntConstant(module, "NF_ACCEPT", NF_ACCEPT);
    PyModule_AddIntConstant(module, "NF_STOLEN", NF_STOLEN);
    PyModule_AddIntConstant(module, "NF_QUEUE", NF_QUEUE);
    PyModule_AddIntConstant(module, "NF_REPEAT", NF_REPEAT);
    PyModule_AddIntConstant(module, "NF_STOP", NF_STOP);
}
