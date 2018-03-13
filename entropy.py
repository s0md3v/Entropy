import re
import sys
from fuzzywuzzy import fuzz
from math import log

signatures = []
with open ('signatures.txt', 'r') as db:
    for line in db:
        signatures.append(line.strip('/n'))

if sys.version_info < (3, 0):
    input = raw_input

def s_entropy(payload):
    entropy = 0
    for number in range(256):
        result = float(payload.count(chr(number)))/len(payload)
        if result != 0:
            entropy = entropy - result * log(result, 2)
    return entropy

score = 0

def check(payload, score):
    if payload == '':
        print ('Passed')
    shannon = s_entropy(payload)
    if shannon > 4:
        print ('Blocked for having high shannon entropy')
    else:
        similar = 0
        for signature in signatures:
            similarity = fuzz.partial_ratio(signature, payload)
            if similarity > 90:
                similar += 1
        matches = re.findall(r'[\.\'%#&()\+/:;<=>\?\\\[\]`{}"]', payload)
        score += len(matches) + 0.00001
        if len(payload) > 6 and (len(payload) - score) <= len(payload)/2:
            print ('Blocked for having high special char ratio')
        elif (log(score)/log(2)) * len(payload) > 50:
            print ('Blocked for having high entropy')
        elif re.search(r'(<[^>]*alert*\)|<*prompt[^>]*\)|<[^>]*confirm[^>]*\)|<[^>]*alert[^>]*`|<[^>]*prompt[^>]*`|<[^>]*confirm[^>]*`).(?i)', payload):
            print ('Blocked by regex based XSS filter')
        elif re.search(r'((?=.*select)(?=.*from)(?=.*from)(?=.*where)|(?=.*union)(?=.*select)).(?i)', payload):
            print ('Blocked by regex based SQLi filter')
        elif len(payload) > 6 and similar >= 1:
            print ('Blocked for matching with a signature')
        else:
            print ('Passed')

def initiate():
    payload = input('Enter a payload: ').lower()
    check(payload, score)
    initiate()

initiate()