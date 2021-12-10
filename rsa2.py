import rsa
import json

# pub, pri = rsa.newkeys(1024)
# print(pub.__getattribute__('n'))
# rsa.PublicKey(pub.__getattribute__('n'), pub.__getattribute__('e'))
# print(pub.__getattribute__('n'))

data =  f'{{ "tls_version":{{"1":"1"}}}}'
json1 = json.loads(data)
print(json1['tls_version']['1'])