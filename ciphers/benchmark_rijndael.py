import rijndael,time

start = time.time()

key = 'This is our secret key that is .'
testdata = 'a' * 16

encryptor = rijndael.get_class()(key)

for i in range(0,10240):
    if not encryptor.decrypt(encryptor.encrypt(testdata)) == testdata:
        print "Error!"
        exit()
stop = time.time()

print "Time cost: %f seconds." % (stop - start)
