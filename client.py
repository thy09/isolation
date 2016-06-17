import httplib

client = None

try:
	client = httplib.HTTPSConnection('localhost', 443, timeout=30)
	client.request('GET', '/auth')

	response = client.getresponse()
	print response.status
	print response.reason
	print response.read()
except Exception, e:
	print e
finally:
	if client:
		client.close()

