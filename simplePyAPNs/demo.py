# coding=utf-8
"""
desc..
    :copyright: (c) 2016 by fangpeng(@beginman.cn).
    :license: MIT, see LICENSE for more details.
"""
from __future__ import division
from apns import Payload, APNs, Frame
import time, random

def main():
    tokens = ['7bbfac9882c5949ab62bf8ca9a7878d90aa45f091df4392cde01c701c9b7bb40',
              '7bbfac9882c5949ab62bf8ca9a7878d90aa45f091df4392cde01c701c9b7bb40']

    apns = APNs('newfile.crt.pem', 'newfile.key.pem', env='push_prod')

    # get feedback
    for obj in apns.feedback():
        print obj

    # send multi msgs
    frame = Frame()
    identifier = 1
    expiration = time.time()+3600
    priority = 10
    for token_hex in tokens:
        payload = Payload(alert="hello" + str(random.random()), badge=1)
        frame.add_item(token_hex, payload, identifier, expiration, priority)
    apns.send_multi(frame)

    # send single msg
    apns.send('7bbfac9882c5949ab62bf8ca9a7878d90aa45f091df4392cde01c701c9b7bb40', Payload(alert='hello'))

if __name__ == '__main__':
    main()