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
            List<int> plainMatrix = new List<int>();
            List<int> cipherMatrix = new List<int>();
            for (int i = 0; i < plainText.Count; i += 2)
            {
                for (int j = i; j < plainText.Count; j += 2)
                {
                    plainMatrix.Add(plainText[i]);
                    plainMatrix.Add(plainText[i + 1]);
                    plainMatrix.Add(plainText[j]);
                    plainMatrix.Add(plainText[j + 1]);

                    cipherMatrix.Add(cipherText[i]);
                    cipherMatrix.Add(cipherText[i + 1]);
                    cipherMatrix.Add(cipherText[j]);
                    cipherMatrix.Add(cipherText[j + 1]);
                    plainMatrix = matrixInverse2D(plainMatrix);

                    if (plainMatrix.Count > 1)
                    {
                        List<int> keyMatrix = new List<int>();
                        keyMatrix.Add((cipherMatrix[0] * plainMatrix[0] + cipherMatrix[2] * plainMatrix[1]) % 26);
                        keyMatrix.Add((cipherMatrix[0] * plainMatrix[2] + cipherMatrix[2] * plainMatrix[3]) % 26);
                        keyMatrix.Add((cipherMatrix[1] * plainMatrix[0] + cipherMatrix[3] * plainMatrix[1]) % 26);
                        keyMatrix.Add((cipherMatrix[1] * plainMatrix[2] + cipherMatrix[3] * plainMatrix[3]) % 26);
                        return keyMatrix;
                    }
                    plainMatrix.Clear();
                    cipherMatrix.Clear();
                }
            }
            throw new InvalidAnlysisException();
        }

        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            List<int> plainList = new List<int>();
            //int[,] plainMatrix = new int[3,3];
            List<int> cipherList = new List<int>();
            for (int i = 0; i < plainText.Count; i += 3)
            {
                for (int j = i; j < plainText.Count; j += 3)
                {
                    plainList.Add(plainText[i]);
                    plainList.Add(plainText[i + 1]);
                    plainList.Add(plainText[i + 2]);
                    plainList.Add(plainText[j]);
                    plainList.Add(plainText[j + 1]);
                    plainList.Add(plainText[j + 2]);
                    plainList.Add(plainText[j + 3]);
                    plainList.Add(plainText[j + 4]);
                    plainList.Add(plainText[j + 5]);

                    cipherList.Add(cipherText[i]);
                    cipherList.Add(cipherText[i + 1]);
                    cipherList.Add(cipherText[i + 2]);
                    cipherList.Add(cipherText[j]);
                    cipherList.Add(cipherText[j + 1]);
                    cipherList.Add(cipherText[j + 2]);
                    cipherList.Add(cipherText[j + 3]);
                    cipherList.Add(cipherText[j + 4]);
                    cipherList.Add(cipherText[j + 5]);
                    //get plain text inverse p^-1
                    plainList = matrixInverse3D(plainList);

                    if (plainList.Count > 1)
                    {
                        List<int> keyMatrix = new List<int>();
                        keyMatrix = multiply(cipherList, plainList);
                        return keyMatrix;
                    }
                    plainList.Clear();
                    cipherList.Clear();
                }
            }
            throw new InvalidAnlysisException();
        }

        private List<int> multiply(List<int> cipherList, List<int> plainList)
        {
            int[,] plainMatrix = new int[3, 3];
            int[,] cipherMatrix = new int[3, 3];
            int[,] res = new int[3,3];
            List<int> _out = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    plainMatrix[i, j] = plainList[i * 3 + j];
                    cipherMatrix[i, j] = cipherList[i * 3 + j];
                }
            }
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    for (int k = 0; k < 3; k++)
                    {
                        res[i, j] +=plainMatrix[i, k] * cipherMatrix[k, j];
                    }
                }
            }
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    while (res[i, j] < 0)
                        res[i, j] += 26;
                    res[i, j] %= 26;
                }
            }
            int[,] tmp = new int[3, 3];
            //copy matrix to transpose
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    tmp[i, j] = res[i, j];
                }
            }
            //transpose
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    res[i, j] = tmp[j, i];
                }
            }
            //convert matrix to list
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    _out.Add(res[i, j]);
                }
            }
            return _out;
        }

        private List<int> matrixInverse3D(List<int> plainList)
        {
            int[,] plainMatrix = new int[3, 3];
            for (int i = 0; i < 3; i += 1)
            {
                for (int j = 0; j < 3; j++)
                {
                    plainMatrix[i, j] = plainList[i*3 + j];
                }
            }
            int det = calculateDet3D(plainMatrix);
            int b = extendedEuclidean(det);
            if (det != 0 && b != 0)
            {
                plainMatrix = getMatrixInverseTransposed(plainMatrix, b);
                plainList.Clear();
                for (int i = 0; i < 3; i += 1)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        plainList.Add(plainMatrix[i, j]);
                    }
                }
                return plainList;
            }
            return new List<int> { -1 };
        }

        private List<int> matrixInverse2D(List<int> mat)
        {
            List<int> matInverse = new List<int>();
            int b = 0;

            int det = (mat[0] * mat[3] - mat[1] * mat[2]) % 26;
            while (det < 0)
                det += 26;
            b = calculateB(det);
            if (det != 0 && b !=0)
            {
                matInverse.Add((b * mat[3]) % 26);
                matInverse.Add((b * mat[1] * -1) % 26);
                matInverse.Add((b * mat[2] * -1) % 26);
                matInverse.Add((b * mat[0]) % 26);
                //for numbers less than ZERO
                for (int i = 0; i < matInverse.Count; i++)
                {
                    while (matInverse[i] < 0)
                        matInverse[i] += 26;   
                }
            }
            else
            {
                return new List<int> { -1 };
            }

            return matInverse;
        }


        /// <summary>
        ///     calculate the deteminant of the matrix
        /// </summary>
        /// <param name="mat"></param>
        /// <returns></returns>
        //private int[,] matDeterminant2D(int[,] mat, int b)
        //{
        //    int[,] matInverse = new int[2, 2];
        //    matInverse[1, 1] = (b * mat[3]) % 26;
        //    matInverse[0, 1] = (b * mat[1] * -1) % 26;
        //    matInverse[1, 0] = (b * mat[2] * -1) % 26;
        //    matInverse[0, 0] = (b * mat[0]) % 26;
        //}
        private int calculateB(int det)
        {
            for (int i = 2; i < 26; i++)
            {
                if ((det * i) % 26 == 1)
                    return i;
            }
            return 0;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            string _cipherText="", _key="", plainText="";
            List<int> plainList = new List<int>();
            for (int i = 0; i < cipherText.Count; i++)
            {
                _cipherText += alphabetIndex(cipherText[i]);
            }
            for (int i = 0; i < key.Count; i++)
            {
                _key += alphabetIndex(key[i]);
            }
            plainText = Decrypt(_cipherText, _key);
            for (int i = 0; i < plainText.Length; i++)
            {
                plainList.Add(alphabetIndex(plainText[i]));
            }
            return plainList;
        }

        private string Decrypt(string cipherText, string key)
        {
            int mDim = (int)Math.Sqrt(key.Length);
            int nDim = cipherText.Length / mDim;
            int det = 0;
            int[,] cipherMatrix = new int[mDim, nDim];
            int[,] keyMatrix = new int[mDim, mDim];
            int[,] matrixResult = new int[mDim, nDim];
            char[,] plainMatrix = new char[mDim, nDim];

            int cnt = -1;
            for (int i = 0; i < nDim; i++)
            {
                for (int j = 0; j < mDim; j++)
                {
                    cipherMatrix[j, i] = alphabetIndex(cipherText[++cnt]);
                }
            }
            for (int i = 0; i < mDim * mDim; i++)
            {
                keyMatrix[i / mDim, i % mDim] = alphabetIndex(key[i]);
            }

            /// if key is 2D matrix 
            /// calculate inverse
            if (mDim == 2)
            {
                int tmp = 0;
                det = keyMatrix[0,0] * keyMatrix[1,1] - keyMatrix[0,1] * keyMatrix[1,0];
                keyMatrix[0, 1] *= -1;
                keyMatrix[1, 0] *= -1;
                tmp =  keyMatrix[1,1];
                keyMatrix[1, 1] = keyMatrix[0, 0];
                keyMatrix[0, 0] = tmp;
            }
            else if(mDim ==3)
            {
                det = calculateDet3D(keyMatrix);
               
            }
            while (det < 0)
                det += 26;
            if (det == 0)
            {
                throw new NotImplementedException();
            }
            int b = extendedEuclidean(det);
            if (mDim == 2)
            {
                for (int i = 0; i < mDim; i++)
                {
                    for (int j = 0; j < mDim; j++)
                    {
                        while (keyMatrix[i, j] < 0)
                            keyMatrix[i, j] += 26;
                        keyMatrix[i, j] = (keyMatrix[i, j] * b ) % 26;
                        if(keyMatrix[i,j]==0)
                            throw new NotImplementedException();
                    }
                }
            }
            else if (mDim == 3)
            {
                keyMatrix = getMatrixInverseTransposed(keyMatrix, b);
            }

            matrixResult = matMultiplication(keyMatrix, cipherMatrix);
            plainMatrix = getText(matrixResult);
            return getcipherAsPLain(plainMatrix);
        }

        private int[,] getMatrixInverseTransposed(int[,] keyMatrix, int b)
        {
            int[,] tmp = new int[3, 3];
            tmp[0, 0] = (b * (keyMatrix[1, 1] * keyMatrix[2, 2] - keyMatrix[1, 2] * keyMatrix[2, 1])) % 26;
            tmp[0, 1] = (-1 * b * (keyMatrix[1, 0] * keyMatrix[2, 2] - keyMatrix[1, 2] * keyMatrix[2, 0])) % 26;
            tmp[0, 2] = (b * (keyMatrix[1, 0] * keyMatrix[2, 1] - keyMatrix[1, 1] * keyMatrix[2, 0])) % 26;
            tmp[1, 0] = (-1 * b * (keyMatrix[0, 1] * keyMatrix[2, 2] - keyMatrix[0, 2] * keyMatrix[2, 1])) % 26;
            tmp[1, 1] = (b * (keyMatrix[0, 0] * keyMatrix[2, 2] - keyMatrix[0, 2] * keyMatrix[2, 0])) % 26;
            tmp[1, 2] = (-1 * b * (keyMatrix[0, 0] * keyMatrix[2, 1] - keyMatrix[0, 1] * keyMatrix[2, 0])) % 26;
            tmp[2, 0] = (b * (keyMatrix[0, 1] * keyMatrix[1, 2] - keyMatrix[0, 2] * keyMatrix[1, 1])) % 26;
            tmp[2, 1] = (-1 * b * (keyMatrix[0, 0] * keyMatrix[1, 2] - keyMatrix[0, 2] * keyMatrix[1, 0])) % 26;
            tmp[2, 2] = (b * (keyMatrix[0, 0] * keyMatrix[1, 1] - keyMatrix[0, 1] * keyMatrix[1, 0])) % 26;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    while (tmp[i, j] < 0)
                        tmp[i, j] += 26;
                }
            }
            //transpose
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    keyMatrix[i, j] = tmp[j, i];
                }
            }
            return keyMatrix;
        }

        private int calculateDet3D(int[,] keyMatrix)
        {
            int det = 0;
            det += keyMatrix[0, 0] * (keyMatrix[1, 1] * keyMatrix[2, 2] - keyMatrix[1, 2] * keyMatrix[2, 1]);
            det += -1 * keyMatrix[0, 1] * (keyMatrix[1, 0] * keyMatrix[2, 2] - keyMatrix[1, 2] * keyMatrix[2, 0]);
            det += keyMatrix[0, 2] * (keyMatrix[1, 0] * keyMatrix[2, 1] - keyMatrix[1, 1] * keyMatrix[2, 0]);
            det %= 26;
            return det;
        }
        /// <summary>
        ///     get the inverse of b where bInverse = det power -1
        /// </summary>
        /// <param name="det"></param>
        /// <returns></returns>
        private int extendedEuclidean(int det)
        {
            int Q, A1 = 1, A2 = 0, A3 = 26, B1 = 0, B2 = 1, B3 = det;
            int _Q, _A1, _A2, _A3, _B1, _B2, _B3;
            while (true)
            {
                if (B3 == 0 || B3 == 1)
                    break;
                _Q = A3 / B3;
                _A1 = B1;
                _A2 = B2;
                _A3 = B3;
                _B1 = A1 - (_Q * B1);
                _B2 = A2 - (_Q * B2);
                _B3 = A3 % B3;
                Q =  _Q;
                A1 = _A1;
                A2 = _A2;
                A3 = _A3;
                B1 = _B1;
                B2 = _B2;
                B3 = _B3;

            }
            while (B2 < 0)
                B2 += 26;

            if (B2 >= 26)
                B2 = B2 % 26;
            return B2;
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
                cipherMatrix = getText(matrixResult);

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

        private char[,] getText(int[,] matrixResult)
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
