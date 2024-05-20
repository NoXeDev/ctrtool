add_requires("openssl")

target("ctrtool")
    add_files("*.c")

    add_packages("openssl")