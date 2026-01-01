#!/usr/bin/env python3

import os
import sys
from code import start
if __name__ == "__main__":
    
    try:
        os.system("clear")
        start()
    except KeyboardInterrupt:
        print("\nProceso cancelado")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
