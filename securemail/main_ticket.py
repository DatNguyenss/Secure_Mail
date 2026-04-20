"""Ticket Service entry point."""
from securemail.ticket_service import as_tgs_server


if __name__ == "__main__":
    as_tgs_server.serve()
