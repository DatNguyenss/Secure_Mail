"""KDS server entry point."""
from securemail.kds import kds_server


if __name__ == "__main__":
    kds_server.serve()
