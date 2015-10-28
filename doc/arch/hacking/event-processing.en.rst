.. Licensed to the Apache Software Foundation (ASF) under one
   or more contributor license agreements.  See the NOTICE file
   distributed with this work for additional information
   regarding copyright ownership.  The ASF licenses this file
   to you under the Apache License, Version 2.0 (the
   "License"); you may not use this file except in compliance
   with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.

.. Referenced source files

.. |I_EThread.h| replace:: ``I_EThread.h``

.. _I_EThread.h: https://github.com/apache/trafficserver/blob/master/iocore/eventsystem/I_EThread.h

.. |I_ProtectedQueue.h| replace:: ``I_ProtectedQueue.h``

.. _I_ProtectedQueue.h: https://github.com/apache/trafficserver/blob/master/iocore/eventsystem/I_ProtectedQueue.h

.. |I_PriorityEventQueue.h| replace:: ``I_PriorityEventQueue.h``

.. _I_PriorityEventQueue.h: https://github.com/apache/trafficserver/blob/master/iocore/eventsystem/I_PriorityEventQueue.h

.. |UnixEThread.cc| replace:: ``UnixEThread.cc``

.. _UnixEThread.cc: https://github.com/apache/trafficserver/blob/master/iocore/eventsystem/UnixEThread.cc


Event Processing
=====================================

Traffic Server is a multi-threaded event driven system. Although there are multiple threads these
are not dedicated to any particular connection or transaction. Each transaction generates events and
these events are then processed to move the transaction forward. Event processing threads are
divided in to "NET" and "TASK" threads. The thread itself is represented by an instance
of the class ``EThread`` defined in |I_EThread.h|_.

Event Object
------------

Event Queues
-------------

The primary event queue is a set of timed buckets, ordered by quantized wait times. These are stored
in the ``after`` array in an instance of ``PriorityEventQueue`` defined in
|I_PriorityEventQueue.h|_. When queued the event is placed in the bucket representing the smallest
wait that is at least as long as the event wait time. For instance an event due in 7ms would be
placed in the 10ms bucket because the next shorter (5ms) is shorter than the event wait time. It
would not be placed in the 20ms because 10ms is long enough and shorter than 20ms.

The method ``PriorityEventQueue::check_ready`` moves events between buckets due to the passage of
time. Each time it is called it selects a bucket and checks events in that bucket and all shorter
ones, moving events to the newly appropriate bucket with regard to the current time. The selection
is done by dividing the time by the duration of the shortest bucket. Because the bucket times are
all powers of 2 of the shortest time this produces a bit vector, one bit for each bucket, each bit
oscillating with the same frequency as the bucket duration. This vector is xor'd with the previous
vector yielding one that has a bit set for each bucket duration that has changed. The bit for the
longest duration is found and that bucket, along with all shorter duration buckets, is emptied and
the content re-inserted in the appropriate buckets for the current time.

.. note::
   This works well if the check times are more frequent than the shortest duration but may be
   problematic if the checks are spaced more than twice a duration (in which case the bit will flip
   and then flip back). This may not be a problem because as long as a longer duraction bucket is
   checked, the shorter duration ones will be as well.

Events can be scheduled on a thread by other threads. Each event processing thread has an external
queue which is contained in an instance of ``ProtectedQueue`` defined in |I_ProtectedQueue.h|_. Cross thread
scheduling is done by adding an event to this list. These lists are thread safe for multiple
additions as long as only one thread (the owner) removes events from it. There is a lock associated
with this queue for handlling the empty queue case. In this situation the event processor does a
timed wait on a condition variable. The POSIX interface to this mechanism requires a mutex. More
details on this are described later in `Event Loop`_.

The ``ProtectedQueue`` instance also has a local queue which is used to schedule events for a thread
from within the thread.

Event Loop
----------

The basic event loop is in ``EThread::execute`` in |UnixEThread.cc|_. Events are processed in
priority order which is

#. ``IMMEDIATE`` -- events to be processed as soon as possible.
#. ``INTERVAL`` -- timed events for which the scheduled time has passed.
#. ``NEGATIVE`` -- events with a negative periodicity. Currently only I/O events have this property.

The first phase dequeues the local event queue in ``ProtectedQueue``. Immediate events are
dispatched in the loop. Timed events are placed in the ``PriorityEventQueue``. Negative events
(those with a timeout time of less than zero) are put in a local "negative queue" in order from most
negative (greatest absolute value) to least negative.

After this the time based event buckets are updated via ``check_ready`` which moves events forward
in the buckets based on the current time. Events in the shortest duration bucket are dequeued and
dispatched until the queue is empty or a cancelled event is encountered.