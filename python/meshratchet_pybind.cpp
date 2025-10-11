// python/meshratchet_pybind.cpp
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "../include/MeshRatchet.hpp"
#include <pybind11/detail/common.h>

namespace py = pybind11;
using namespace meshratchet;

PYBIND11_MODULE(meshratchet, m) {
    m.doc() = "MeshRatchet Protocol - Python bindings";

    py::register_exception<MeshRatchetError>(m, "MeshRatchetError");

    py::class_<Context>(m, "Context")
        .def(py::init<const mr_config_t*>(), py::arg("config") = nullptr);

    py::class_<KeyPair>(m, "KeyPair")
        .def_static("generate", &KeyPair::generate, py::arg("ctx"), py::arg("quantum") = false)
        .def("public_key", [](const KeyPair& self) {
            return py::bytes(reinterpret_cast<const char*>(self.public_key()), 32);
        })
        .def("is_quantum_resistant", &KeyPair::is_quantum_resistant);

    py::class_<Session>(m, "Session")
        .def_static("create", &Session::create,
            py::arg("ctx"), py::arg("local_key"), py::arg("remote_pubkey"), py::arg("mode") = MR_MODE_STANDARD)
        .def("encrypt", [](Session& self, int msg_type, const py::bytes& plaintext) {
            std::string pt = plaintext;
            auto ct = self.encrypt(static_cast<mr_msg_type_t>(msg_type),
                                  std::vector<uint8_t>(pt.begin(), pt.end()));
            return py::bytes(reinterpret_cast<const char*>(ct.data()), ct.size());
        })
        .def("decrypt", [](Session& self, const py::bytes& ciphertext) {
            std::string ct = ciphertext;
            mr_msg_type_t msg_type;
            auto pt = self.decrypt(std::vector<uint8_t>(ct.begin(), ct.end()), msg_type);
            return py::make_tuple(
                py::bytes(reinterpret_cast<const char*>(pt.data()), pt.size()),
                static_cast<int>(msg_type)
            );
        });
}