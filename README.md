# test

private readonly RequestDelegate _next;

        private static byte[] encryptionKey = Encoding.ASCII.GetBytes("1njanrhdkCnsahrebfdMvbjo32hqnd31");
        private static byte[] initialization_vector = Encoding.ASCII.GetBytes("jsKidmshatyb4jdu");


        public EncryptionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            X509Certificate2 myCert = LoadCertificate(StoreLocation.LocalMachine, "E=f, CN=f, OU=f, O=ff, L=ff, S=ff, C=ff");

            //string myText = "This is the text I wish to encrypt";

            //string encrypted = Encrypt(myCert, myText);

            //string decrypted = Decrypt(myCert, encrypted);

            httpContext.Response.Body = EncryptStream(httpContext.Response.Body);

            if (httpContext.Request.QueryString.HasValue)
            {
                string decryptedString = DecryptString(httpContext.Request.QueryString.Value.Substring(9));
                httpContext.Request.QueryString = new QueryString($"?{decryptedString}");
            }

            string bodyData = await new StreamReader(httpContext.Request.Body).ReadToEndAsync();
            if (httpContext.Request.Method != "Get" && !string.IsNullOrEmpty(bodyData))
            {
                BodyData bodyModel = JsonConvert.DeserializeObject<BodyData>(bodyData);
                if(bodyModel != null)
                {
                    string bodyDataString = DecryptString(bodyModel.payload);
                    httpContext.Request.Body = GenerateStreamFromString(bodyDataString);
                }                  
            }
         
            await _next(httpContext);
            await httpContext.Request.Body.DisposeAsync();
            await httpContext.Response.Body.DisposeAsync();
        }

       
        public static X509Certificate2 LoadCertificate(StoreLocation storeLocation, string certificateName)
        {
            X509Store store = new X509Store(storeLocation);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection =
               store.Certificates;
            X509Certificate2 cert =
               certCollection.Cast<X509Certificate2>().FirstOrDefault
               (c => c.Subject == certificateName);
            if (cert == null)
                Console.WriteLine("NO Certificate named " +
                   certificateName + " was found in your certificate store");
            store.Close();
            return cert;
        }

        private static string Encrypt(X509Certificate2 x509, string stringToEncrypt)
        {
            if (x509 == null || string.IsNullOrEmpty(stringToEncrypt))
                throw new Exception("A x509 certificate and string for encryption must be provided");

            RSA rsa = (RSA)x509.GetRSAPublicKey();
 
            //RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)x509.PrivateKey;
            byte[] bytestoEncrypt = ASCIIEncoding.ASCII.GetBytes(stringToEncrypt);
            byte[] encryptedBytes = rsa.Encrypt(bytestoEncrypt, RSAEncryptionPadding.OaepSHA256);
            return Convert.ToBase64String(encryptedBytes);
        }

        private static string Decrypt(X509Certificate2 x509, string stringTodecrypt)
        {
            if (x509 == null || string.IsNullOrEmpty(stringTodecrypt))
                throw new Exception("A x509 certificate and string for decryption must be provided");

            if (!x509.HasPrivateKey)
                throw new Exception("x509 certicate does not contain a private key for decryption");

            //RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)x509.PrivateKey;
            RSA rsa = (RSA)x509.GetRSAPublicKey();
            byte[] bytestodecrypt = Convert.FromBase64String(stringTodecrypt);
            byte[] plainbytes = rsa.Decrypt(bytestodecrypt, RSAEncryptionPadding.OaepSHA256);
            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
            return enc.GetString(plainbytes);
        }

        private static Stream EncryptStream(X509Certificate2 x509, Stream stringToEncrypt)
        {
            //if (x509 == null || string.IsNullOrEmpty(stringToEncrypt))
            //    throw new Exception("A x509 certificate and string for encryption must be provided");

            RSA rsa = (RSA)x509.GetRSAPublicKey();

            //RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)x509.PrivateKey;
            byte[] bytestoEncrypt = streamToByteArray(stringToEncrypt);
            byte[] encryptedBytes = rsa.Encrypt(bytestoEncrypt, RSAEncryptionPadding.OaepSHA256);
            return new MemoryStream(encryptedBytes);
        }

        private static Stream DecryptStream(X509Certificate2 x509, Stream stringTodecrypt)
        {
            //if (x509 == null || string.IsNullOrEmpty(stringTodecrypt))
            //    throw new Exception("A x509 certificate and string for decryption must be provided");

            if (!x509.HasPrivateKey)
                throw new Exception("x509 certicate does not contain a private key for decryption");

            //RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)x509.PrivateKey;
            RSA rsa = (RSA)x509.GetRSAPrivateKey();
            byte[] bytestodecrypt = streamToByteArray(stringTodecrypt);
            byte[] plainbytes = rsa.Decrypt(bytestodecrypt, RSAEncryptionPadding.OaepSHA256);
            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
            return new MemoryStream(plainbytes);
        }

        public static byte[] streamToByteArray(Stream input)
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }
        public static Stream GenerateStreamFromString(string s)
        {
            var stream = new MemoryStream();
            var writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

        // old

        private static CryptoStream EncryptStream(Stream responseStream)
        {
            Aes aes = GetEncryptionAlgorithm();

            ToBase64Transform base64Transform = new ToBase64Transform();
            CryptoStream base64EncodedStream = new CryptoStream(responseStream, base64Transform, CryptoStreamMode.Write);
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            CryptoStream cryptoStream = new CryptoStream(base64EncodedStream, encryptor, CryptoStreamMode.Write);

            return cryptoStream;
        }

        private static Aes GetEncryptionAlgorithm()
        {
            Aes aes = Aes.Create();
            aes.Key = encryptionKey;
            aes.IV = initialization_vector;

            return aes;
        }

        private static CryptoStream DecryptStream(Stream cipherStream)
        {
            Aes aes = GetEncryptionAlgorithm();

            FromBase64Transform base64Transform = new FromBase64Transform(FromBase64TransformMode.IgnoreWhiteSpaces);
            CryptoStream base64DecodedStream = new CryptoStream(cipherStream, base64Transform, CryptoStreamMode.Read);
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            CryptoStream decryptedStream = new CryptoStream(base64DecodedStream, decryptor, CryptoStreamMode.Read);
            return decryptedStream;
        }

        private static string DecryptString(string cipherText)
        {
            Aes aes = GetEncryptionAlgorithm();
            byte[] buffer = Convert.FromBase64String(cipherText);

            using MemoryStream memoryStream = new MemoryStream(buffer);
            using ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            using StreamReader streamReader = new StreamReader(cryptoStream);
            return streamReader.ReadToEnd();
        }

        private static CryptoStream DecryptStringStream(string cipherText)
        {
            Aes aes = GetEncryptionAlgorithm();
            byte[] buffer = Convert.FromBase64String(cipherText);

            using MemoryStream memoryStream = new MemoryStream(buffer);
            using ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            using StreamReader streamReader = new StreamReader(cryptoStream);
            return cryptoStream;
        }
    }
