import serpent,time

start = time.time()

key = 'This is our secret key that is .'
testdata = 'a' * 16

encryptor = serpent.Serpent(key)

for i in range(0,10240):
    if not encryptor.decrypt(encryptor.encrypt(testdata)) == testdata:
        print "Error!"
        exit()
stop = time.time()

print "Time cost: %f seconds." % (stop - start)
