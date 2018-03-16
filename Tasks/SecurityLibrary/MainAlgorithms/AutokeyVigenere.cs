using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        private char[,] vigenereTable = new char[26, 26];

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
            for (int i = 0; i < keyStream.Length; i++)
            {
                if (plainText.Substring(0, keyStream.Length-i) == keyStream.Substring(i, keyStream.Length - i))
                {
                    _out = keyStream.Substring(0, i);
                    return _out;

                }
            }
            return _out;
        }

        public string Decrypt(string cipherText, string key)
        {
            
            createVigenereTable();
            string _out = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (vigenereTable[j, key[i] - 97] == cipherText[i])
                    {
                        _out += (char)(j + 97);
                        key += _out[i];
                        break;
                    }
                }
            }
            return _out;
        }

        public string Encrypt(string plainText, string key)
        {
            string _out = "";
            createVigenereTable();
            key = getKeyStream(plainText, key);
            key = getKeyStream(plainText, key);
            for (int i = 0; i < plainText.Length; i++)
            {
                _out += vigenereTable[plainText[i] - 97, key[i] - 97];
            }
            return _out;
        }

        private string getKeyStream(string plainText, string key)
        {
            int diff = plainText.Length - key.Length;
            if (diff > 0)
            {
                for (int i = 0; i < diff; i++)
                {
                    key += plainText[i];

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
