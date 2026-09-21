"""History must preserve wire u64 sequence values and private file modes."""
import os
from pathlib import Path
import stat
import tempfile
import unittest

from meshctl import history


class HistoryTests(unittest.TestCase):
    def test_unsigned_sequence_survives_database_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.db'
            values = (2**63 - 1, 2**63, 2**64 - 1)
            connection = history.open_history(path)
            try:
                for sequence in values:
                    history.record_message(connection, contact='peer', direction='in',
                                           epoch=2**32 - 1, sequence=sequence, text='message')
            finally:
                connection.close()
            connection = history.open_history(path)
            try:
                rows = history.recent_messages(connection)
                self.assertEqual([row[3] for row in rows], list(reversed(values)))
            finally:
                connection.close()

    def test_existing_database_is_made_private_before_use(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.db'
            path.touch()
            os.chmod(path, 0o666)
            connection = history.open_history(path)
            try:
                history.record_message(connection, contact='peer', direction='in',
                                       epoch=1, sequence=1, text='private message')
                for candidate in Path(directory).iterdir():
                    self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o600)
            finally:
                connection.close()


if __name__ == '__main__':
    unittest.main()
