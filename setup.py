import setuptools
import glob

setuptools.setup(
    name="blog",
    version="0.0.1",
    author="suplinux",
    author_email="2501148856@qq.com.com",
    description="A small example package",
    long_description_content_type="text/markdown",
    url="http:47.95.243.182",
    packages=setuptools.find_packages(),
    data_files = glob.glob("templates/*.html") + ["requirement.txt"],
    python_requires='>=3.6',
)