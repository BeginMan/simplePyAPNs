# coding=utf-8
"""
desc..
    :copyright: (c) 2016 by fangpeng(@beginman.cn).
    :license: MIT, see LICENSE for more details.
"""
from apns import Payload, APNs

token = '7bbfac9882c5949ab62bf8ca9a7878d90aa45f091df4392cde01c701c9b7bb40'

payload = Payload('test for simplePyAPNs', extra={"name": "BeginMan"})
apns = APNs('newfile.crt.pem', 'newfile.key.pem', env='push_prod')
apns.send(token, payload)
