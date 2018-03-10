using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            string _plainText = "", _key = "";
            List<int> cipherList = new List<int>();
            for (int i = 0; i < plainText.Count; i++)
            {
                _plainText += alphabetIndex(plainText[i]);
            }
            for (int i = 0; i < key.Count; i++)
            {
                _key += alphabetIndex(key[i]);
            }

            string cipherText = Encrypt(_plainText, _key);
            for (int i = 0; i < cipherText.Length; i++)
            {
                cipherList.Add(alphabetIndex(cipherText[i]));
            }
            return cipherList;
            
        }

        private string Encrypt(string plainText, string key)
        {
            int mDim = (int)Math.Sqrt(key.Length);
            int nDim = plainText.Length / mDim;
            int[,] plainTextMatrix = new int[mDim, nDim];
            int[,] keyMatrix = new int[mDim, mDim];
            int[,] matrixResult = new int[mDim, nDim];
            char[,] cipherMatrix = new char[mDim, nDim];

            int cnt=-1;
            for(int i=0; i<nDim; i++) {
                for(int j=0; j<mDim; j++) {
                    plainTextMatrix[j, i] = alphabetIndex(plainText[++cnt]);
                }
            }

            for (int i = 0; i < mDim * mDim; i++)
            {
                keyMatrix[i / mDim, i % mDim] = alphabetIndex(key[i]);
            }

            if (keyMatrix.GetLength(1) != plainTextMatrix.GetLength(0))
            {
                throw new NotImplementedException();
            }
            else
            {
                matrixResult = matMultiplication(keyMatrix, plainTextMatrix);
                cipherMatrix = getcipherText(matrixResult);

            }

            return getcipherAsPLain(cipherMatrix);
        }

        private string getcipherAsPLain(char[,] cipherMatrix)
        {
            string cipherText = "";
            int mDim = cipherMatrix.GetLength(0);
            int nDim = cipherMatrix.GetLength(1);

            for (int i = 0; i < nDim; i++)
            {
                for (int j = 0; j < mDim; j++)
                {
                    cipherText += cipherMatrix[j, i];
                }
            }
            return cipherText;
        }

        private char[,] getcipherText(int[,] matrixResult)
        {
            int mDim = matrixResult.GetLength(0);
            int nDim = matrixResult.GetLength(1);
            char[,] cipherText = new char[mDim, nDim];

            for (int i = 0; i < mDim; i++)
            {
                for (int j = 0; j < nDim; j++)
                {
                    cipherText[i, j] = alphabetIndex(matrixResult[i, j]);
                }
            }
            return cipherText;
        }

        /// <summary>
        ///     Matrix Multiplication Methodology 
        /// </summary>
        /// <param name="mat1"></param>
        /// <param name="mat2"></param>
        /// <returns></returns>
        private int[,] matMultiplication(int[,] mat1, int[,] mat2)
        {
            int mDim = mat1.GetLength(0);
            int nDim = mat2.GetLength(1);
            int[,] matrixResult = new int[mDim, nDim];

            for (int i = 0; i < mDim; i++)
            {
                for (int j = 0; j < nDim; j++)
                {
                    matrixResult[i, j] = elementMultiply(mat1, mat2, i, j, mDim) %26;
                }
            }
            return matrixResult;
        }

        /// <summary>
        ///     multiplay each element in mat1 * mat2
        /// </summary>
        /// <param name="mat1"></param>
        /// <param name="mat2"></param>
        /// <param name="row"></param>
        /// <param name="col"></param>
        /// <param name="mDim"></param>
        /// <returns></returns>
        private int elementMultiply(int[,] mat1, int[,] mat2, int row, int col, int mDim) 
        {
            int sum = 0;
            for (int i = 0; i < mDim; i++)
            {
                sum += mat1[row, i] * mat2[i, col];
            }
            return sum;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

        private int alphabetIndex(char c)
        {
            char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            for (int i = 0; i < alphabet.Length; i++)
                if (alphabet[i] == c) 
                    return i;
            return -1; 
        }

        private char alphabetIndex(int i)
        {
            char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            return alphabet[i];
        }

    }
}
