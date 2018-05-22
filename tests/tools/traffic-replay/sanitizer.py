import json
import os
import sys
import time
import multiprocessing
from queue import Queue, Empty
from threading import Thread, Barrier
import argparse
from copy import deepcopy
# Default template replay file with basic elements
template = json.loads('{"meta": {"version":"1.0"},"sessions":[]}')

# Read in every n files in indir and combine into one json object
# Put the resulting object into out_q for later writing
def readAndCombine(in_dir, sub_dir, n, out_q):
  count = 0
  smoothie = deepcopy(template)
  sessions = []
  print("Reading {}".format(in_dir))
  for f in os.listdir(in_dir):
    if os.path.isfile(os.path.join(in_dir, f)):
      try:
        fd = open('{}/{}'.format(in_dir, f), 'r', encoding='ascii', errors="surrogateescape")
        try:
          data = json.load(fd)
        except Exception as e:
          print("Failed to load {}/{} as a json object".format(in_dir, f))
          fd.close()
          continue
        count += 1
        sessions.extend(data["sessions"])
        if count % n == 0:
          smoothie["sessions"] = deepcopy(sessions)
          out_q.put(('{}_{}.json'.format(sub_dir, int(count/n)), smoothie))
          smoothie = deepcopy(template)
          sessions = []
      except Exception as e:
        print("Failed to handle {}/{}. ERROR: {}".format(indir, f, e))
        continue
  if sessions:
    smoothie["sessions"] = deepcopy(sessions)
    out_q.put('{}_{}.json'.format(sub_dir, int(count/n)+1), smoothie)

def writeToFile(out_dir, out_q):
  while not out_q.empty():
    try:
      out_data = out_q.get(False)
    except Empty:
      break
    print("Writing {}...".format(out_data[0]))
    with open("{}/{}".format(out_dir,out_data[0]), "w", encoding="ascii", errors="surrogateescape") as f:
      json.dump(out_data[1], f, indent=4)

def sanitize(in_dir, sub_dir, out_dir, n, out_q, barrier):
  readAndCombine(os.path.join(in_dir, sub_dir), sub_dir, n, out_q)
  barrier.wait()
  writeToFile(out_dir, out_q)
  return

if __name__ == "__main__":
  parser = argparse.ArgumentParser()

  parser.add_argument("-i", type=str, dest='in_dir', help="Input directory of log files (from traffic_dump)")
  parser.add_argument("-o", type=str, dest='out_dir', help="Output directory of replay files")
  parser.add_argument("-n", type=int, dest='sessions', default=10, help="Number of sessions in one output file")

  args = parser.parse_args()

  subdir_list = []
  out_q = Queue()

  for subdir in os.listdir(args.in_dir):
    if os.path.isdir(os.path.join(args.in_dir, subdir)):
      subdir_list.append(subdir)

  threads = []
  barrier = Barrier(max(len(subdir), 1), timeout=10)

  for i in range(max(len(subdir), 1)):
    t = Thread(target=sanitize, args=(args.in_dir, subdir_list[i], args.out_dir, args.sessions, out_q, barrier))
    t.start()
    threads.append(t)


