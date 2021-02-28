Clone project from git repo. after clone project you need goto project folder and open cmd and run following commands

1.	Build the app

    mvn clean install
    
2.	Run the app

    mvn exec:java -D"exec.mainClass"="com.rsa.EncryptionDecryption" -Dexec.args="shard-key 5 2"
    
    mvn exec:java -D"exec.mainClass"="com.rsa.EncryptionDecryption" -Dexec.args="encrypt testinputdata.TXT"
    
    mvn exec:java -D"exec.mainClass"="com.rsa.EncryptionDecryption" -Dexec.args="decrypt 5 2 testinputdata.TXT.encrypted"
    
3.	Run the unit tests

    mvn test
