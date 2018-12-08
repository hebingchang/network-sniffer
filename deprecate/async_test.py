import sys
import asyncio
import time

from PyQt5.QtWidgets import QApplication, QProgressBar
from quamash import QEventLoop, QThreadExecutor

app = QApplication(sys.argv)
loop = QEventLoop(app)
asyncio.set_event_loop(loop)  # NEW must set the event loop

progress = QProgressBar()
progress.setRange(0, 99)
progress.show()

async def master():
    await first_50()
    # TODO announce completion?

async def first_50():
    for i in range(50):
        progress.setValue(i)
        await asyncio.sleep(.1)

with loop: ## context manager calls .close() when loop completes, and releases all resources
    loop.run_until_complete(master())