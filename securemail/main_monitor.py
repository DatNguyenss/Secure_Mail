"""SecureMail Monitor entry point.

Run from the project root:
    python -m securemail.main_monitor
"""

from securemail.gui.app import launch


def main():
    launch("monitor")


if __name__ == "__main__":
    main()
