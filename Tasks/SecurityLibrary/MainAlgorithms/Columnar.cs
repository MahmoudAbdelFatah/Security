using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string plainText = "";
            int cnt = -1;
            int rows = cipherText.Length / key.Count;
            int cols = key.Count;
            char[,] mat = new char[rows, cols];
            char[,] tmp = new char[rows, cols];

            for (int i = 0; i < cols; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    mat[j, i] = cipherText[++cnt];
                }
            }

            for (int i = 1; i <= cols; i++)
            {
                int col = key.IndexOf(i);
                for (int j = 0; j < rows; j++)
                {
                    tmp[j, col] = mat[j,i-1];
                }
            }

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    plainText += tmp[i, j];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string cipherText = "";
            while(plainText.Length %key.Count !=0)
                plainText +='x';
            int cnt = -1;
            int rows = plainText.Length / key.Count;
            int cols = key.Count;
            char[,] mat = new char[rows, cols];
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    mat[i, j] = plainText[++cnt];
                }
            }
            for (int i = 1; i <= cols; i++)
            {
                int col = key.IndexOf(i);
                for (int j = 0; j < rows; j++)
                {
                    cipherText += mat[j, col];
                }
            }
            return cipherText;
        }
    }
}
