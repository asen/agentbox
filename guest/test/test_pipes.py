"""FdWriter on owned pipes: the high water and its drain are one condition,
`flushed` (everything written so far left this process) another; every
callback runs once, on the loop."""

import asyncio
import fcntl
import os
import unittest

from guest.src.pipes import FdWriter

PAGE = 4096


class Writer(unittest.IsolatedAsyncioTestCase):
    def pipe(self, keep=True):
        """A one-page pipe; its read end the test's, closed at the end if kept."""
        read, write = os.pipe2(os.O_CLOEXEC)
        fcntl.fcntl(write, fcntl.F_SETPIPE_SZ, PAGE)
        os.set_blocking(read, False)
        if keep:
            self.addCleanup(os.close, read)
        return read, write

    def drain_pipe(self, read):
        try:
            while os.read(read, 65536):
                pass
        except BlockingIOError:
            pass

    async def settle(self):
        for _ in range(5):
            await asyncio.sleep(0)

    async def test_the_high_water_and_the_flush_are_apart(self):
        read, write = self.pipe()
        drains, flushes = [], []
        writer = FdWriter(write, drain=lambda: drains.append(1), high_water=16)
        self.assertTrue(writer.write(b"x" * PAGE))
        # Below the high water but waiting here: no drain is owed.
        self.assertTrue(writer.write(b"y" * 8))
        self.assertEqual(writer.pending, 8)
        writer.flushed(flushes.append)
        await self.settle()
        self.assertEqual((drains, flushes), ([], []))
        self.drain_pipe(read)
        await self.settle()
        self.assertEqual((drains, flushes, writer.pending), ([], [True], 0))
        # At the high water: write says False, the drain follows the empty buffer.
        self.drain_pipe(read)
        self.assertTrue(writer.write(b"x" * PAGE))
        self.assertFalse(writer.write(b"z" * 16))
        self.drain_pipe(read)
        await self.settle()
        self.assertEqual((drains, flushes), ([1], [True]))
        writer.destroy()

    async def test_flushed_on_an_empty_buffer_is_true_on_the_loop(self):
        _, write = self.pipe()
        flushes = []
        writer = FdWriter(write)
        self.assertTrue(writer.write(b"a"))
        writer.flushed(flushes.append)
        self.assertEqual(flushes, [])
        await self.settle()
        self.assertEqual(flushes, [True])
        writer.destroy()

    async def test_destroy_fails_the_waiter_once_and_every_later_one(self):
        _, write = self.pipe()
        flushes, gone = [], []
        writer = FdWriter(write, gone=lambda: gone.append(1))
        writer.write(b"x" * (PAGE + 1))
        writer.flushed(flushes.append)
        writer.destroy()
        writer.destroy()
        writer.flushed(flushes.append)
        self.assertFalse(writer.write(b"more"))
        await self.settle()
        self.assertEqual((flushes, gone), ([False, False], []))

    async def test_a_closed_reader_is_gone_once_and_fails_the_waiter(self):
        read, write = self.pipe(keep=False)
        flushes, gone = [], []
        writer = FdWriter(write, gone=lambda: gone.append(1), watch=True)
        writer.write(b"x" * (PAGE + 1))
        writer.flushed(flushes.append)
        os.close(read)
        await self.settle()
        self.assertEqual((flushes, gone, writer.destroyed, writer.fd), ([False], [1], True, -1))

    async def test_end_closes_once_everything_left(self):
        read, write = self.pipe()
        writer = FdWriter(write)
        writer.end(b"x" * (PAGE + 3))
        self.assertGreaterEqual(writer.fd, 0)
        data = bytearray()
        while True:
            await asyncio.sleep(0.01)
            try:
                chunk = os.read(read, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                break
            data += chunk
        self.assertEqual((len(data), writer.fd, writer.destroyed), (PAGE + 3, -1, False))


if __name__ == "__main__":
    unittest.main()
