#
# The MIT License (MIT)
#
# Copyright (C) 2017 Marcos Pereira <marcospereira.mpj@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


"""
Storage abstraction for CIBA transactions.

The service never touches a database directly. It relies on the
:class:`CibaStorage` protocol, which an application implements on top of its
own transactional store. :class:`InMemoryCibaStorage` is provided for the demo
and for tests; production code should supply a durable implementation whose
``save`` runs inside the same transaction as the surrounding business work.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import CibaStatus, CibaTransaction


@runtime_checkable
class CibaStorage(Protocol):
    """
    Persistence operations required by the CIBA service.

    Implementations must guarantee that :meth:`save` is atomic per transaction
    so that concurrent notifications and polling workers cannot overwrite each
    other's state.
    """

    def get(self, auth_req_id: str) -> CibaTransaction | None:
        """
        Load a transaction by its auth_req_id.

        :param auth_req_id: Authentication request identifier
        :type auth_req_id: str
        :returns: The transaction, or None when unknown
        :rtype: CibaTransaction or None
        """
        ...

    def save(self, transaction: CibaTransaction) -> None:
        """
        Persist a transaction, creating or replacing it atomically.

        :param transaction: Transaction to persist
        :type transaction: CibaTransaction
        """
        ...


class InMemoryCibaStorage:
    """
    Thread-unsafe in-memory storage used by the demo and the test suite.

    It is intentionally simple: keys are auth_req_id values and values are the
    live transaction objects. Do not use it across processes or as a durable
    store.
    """

    def __init__(self) -> None:
        """Initialise an empty store."""
        self._transactions: dict[str, CibaTransaction] = {}

    def get(self, auth_req_id: str) -> CibaTransaction | None:
        """
        Load a transaction by its auth_req_id.

        :param auth_req_id: Authentication request identifier
        :type auth_req_id: str
        :returns: The transaction, or None when unknown
        :rtype: CibaTransaction or None
        """
        return self._transactions.get(auth_req_id)

    def save(self, transaction: CibaTransaction) -> None:
        """
        Persist a transaction in the dictionary.

        :param transaction: Transaction to persist
        :type transaction: CibaTransaction
        """
        if transaction.status not in CibaStatus:  # pragma: no cover - defensive guard
            msg = f"Unknown CIBA status '{transaction.status}'."
            raise ValueError(msg)
        self._transactions[transaction.auth_req_id] = transaction

    def all(self) -> list[CibaTransaction]:
        """
        Return every stored transaction, ordered by initiation time.

        :returns: Stored transactions
        :rtype: list[CibaTransaction]
        """
        return sorted(self._transactions.values(), key=lambda item: item.initiated_at)

    def clear(self) -> None:
        """Remove every transaction."""
        self._transactions.clear()
