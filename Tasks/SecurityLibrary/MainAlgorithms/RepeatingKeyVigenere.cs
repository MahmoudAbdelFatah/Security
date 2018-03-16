using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        private char[,] vigenereTable = new char[26,26];
        

        public string Analyse(string plainText, string cipherText)
        {
            createVigenereTable();
            string keyStream = "", _out = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (vigenereTable[j, plainText[i] - 97] == cipherText[i])
                    {
                        keyStream += (char)(j + 97);
                        break;
                    }
                }
            }
            int len = keyStream.Length;
            for (int i = 1; i <= len; i++)
            {
                if (keyStream.Substring(len - i, i) == keyStream.Substring(0, i))
                {
                    _out = keyStream.Substring(0, len);
                    if ((len - i) == 0)
                        return _out;
                    len = len - (len- (len-i));
                    i = 0;

                }
            }
            return _out;
        }

        public string Decrypt(string cipherText, string key)
        {
            key = getKeyStream(cipherText, key);
            createVigenereTable();
            string _out="";
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (vigenereTable[j, key[i] - 97] == cipherText[i])
                    {
                        _out += (char) (j+97);
                        break;
                    }
                }
            }
            return _out;
        }

        // get string as lower and return it upper :D
        public string Encrypt(string plainText, string key)
        {
            createVigenereTable();
            string _out="";
            key = getKeyStream(plainText, key);
            for (int i = 0; i < plainText.Length; i++)
            {
                _out += vigenereTable[plainText[i]-97, key[i]-97];
            }
            return _out;
        }


        /// <summary>
        ///     get the key stream of the given key to encrypt the plain text use it
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        private string getKeyStream(string plainText, string key)
        {
            int diff = plainText.Length - key.Length;
            if (diff > 0)
            {
                for (int i = 0; i < diff; i++)
                {
                    key += key[i];
                    
                }
            }
            return key;
        }

        /// <summary>
        ///     create the vigenere table for repeating key
        /// </summary>
        private void createVigenereTable()
        {
            int ch = 65;
            for (int i = 0; i < 26; i++)
            {
                ch = i + 65;
                for (int j = 0; j < 26; j++)
                {
                    vigenereTable[i, j] = (char)(ch)++;
                    if (ch > 90)
                        ch = 65;
                }
            }
        }
    }
}