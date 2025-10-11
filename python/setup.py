# python/setup.py
from pybind11.setup_helpers import Pybind11Extension, build_ext
from setuptools import setup
import pybind11
import sysconfig
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Получаем путь к заголовкам Python
python_include = sysconfig.get_path("include")

ext_modules = [
    Pybind11Extension(
        "meshratchet",
        ["python/meshratchet_pybind.cpp"],
        include_dirs=[
            os.path.join(ROOT, "include"),
            python_include,           # ← явно добавляем
            pybind11.get_include(),   # ← заголовки pybind11
        ],
        library_dirs=[ROOT],
        libraries=["meshratchet", "ssl", "crypto"],
        cxx_std=17,
    ),
]

setup(
    name="meshratchet",
    version="0.3.0",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    zip_safe=False,
    python_requires=">=3.6",
    install_requires=["pybind11"],
)