using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace cryptopals
{
	public class Set1
	{
		// Challenge 1: Convert hex to base64
		public static bool Challenge1()
		{
			var hexString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
			var bytes = Convert.FromHexString(hexString);
			var base64 = Convert.ToBase64String(bytes);
			var expectedResult = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

			return base64 == expectedResult;
		}

		// Challenge 2: Fixed XOR
		public static bool Challenge2()
        {
			var buffer1 = "1c0111001f010100061a024b53535009181c";
			var buffer2 = "686974207468652062756c6c277320657965";

			var bytesBuffer1 = Convert.FromHexString(buffer1);
			var bytesBuffer2 = Convert.FromHexString(buffer2);

			var bufferSize = bytesBuffer1.Length;

			byte[] xoredBuffer = new byte[bufferSize];

			// XOR each byte in buffer and add it to the xoredBuffer bytearray
            for (int i = 0; i < bufferSize; i++)
            {
				xoredBuffer[i] = (byte)(bytesBuffer1[i] ^ bytesBuffer2[i]);
            }
			
			var finalBufferString = BitConverter.ToString(xoredBuffer).Replace("-", "").ToLower();
			var expectedResult = "746865206b696420646f6e277420706c6179";

			return finalBufferString == expectedResult;
		}

		// Challenge 3: Single-byte XOR cipher
		public static string Challenge3()
        {
			var buffer = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
			string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789 "; // There is better solution for this, but I couldn't get it working so this is fine.

			Dictionary<char, string> messages = new Dictionary<char, string>();
			Dictionary<char, double> letterScores = new Dictionary<char, double>();

			var bytesBuffer = Convert.FromHexString(buffer);
			var bufferSize = bytesBuffer.Length;

			// Loop through chars and add too messages-dictionary the keys and values that result from XOR-ing
			foreach (var c in chars)
            {
				byte[] xoredBuffer = new byte[bufferSize];

				for (int i = 0; i < bufferSize; i++)
                {
					xoredBuffer[i] = (byte)(bytesBuffer[i] ^ c);
                }
				
				var plainText = Encoding.ASCII.GetString(xoredBuffer);
				messages.Add(c, plainText);

				// Let's score the letter frequencies for this plaintext message
				// First lets get the count of letters in the plaintext
				var letterCount = plainText.ToUpper().GroupBy(x => x).Select(y => new { y.Key, Count = y.Count() });

				double coefficiency = 0;
				// See this crypto stackexchange answer about Bhattacharyya coefficiency https://crypto.stackexchange.com/a/56477
				foreach (var letter in letterCount)
                {
                    if (LetterFrequency.TryGetValue(letter.Key, out var frequency))
                    {
						coefficiency += Math.Sqrt(frequency * letter.Count / plainText.Length);
                    }
                }
				letterScores.Add(c, coefficiency);
			}

			// Get highest scoring key from letterScores
			var highestScore = letterScores.Values.Max();
			var highestScoreKey = letterScores.FirstOrDefault(x => x.Value == highestScore).Key;

			// Get the message by highest scoring key
			var result = messages[highestScoreKey];
			var answer = $"Key is: {highestScoreKey} and decrypted message: {result}";

			return answer;
        }

		// Challenge 4: Detect single-character XOR
		public static string Challenge4()
        {
			// Getting the provided text-file to loop through it
			string sourceFile = @"D:\4.txt";
			IEnumerable<string> fileLines = File.ReadLines(sourceFile);
			string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789 "; // There is better solution for this, but I couldn't get it working so this is fine.
			Dictionary<string, string> messagesAll = new Dictionary<string, string>();
			Dictionary<string, double> letterScoresAll = new Dictionary<string, double>();

			foreach (var line in fileLines)
            {
				Dictionary<char, string> messages = new Dictionary<char, string>();
				Dictionary<char, double> letterScores = new Dictionary<char, double>();

				var bytesBuffer = Convert.FromHexString(line);
				var bufferSize = bytesBuffer.Length;

				// Loop through chars and add too messages-dictionary the keys and values that result from XOR-ing
				foreach (var c in chars)
				{
					byte[] xoredBuffer = new byte[bufferSize];

					for (int i = 0; i < bufferSize; i++)
					{
						xoredBuffer[i] = (byte)(bytesBuffer[i] ^ c);
					}

					var plainText = Encoding.ASCII.GetString(xoredBuffer);
					messages.Add(c, plainText);

					// Let's score the letter frequencies for this plaintext message
					// First lets get the count of letters in the plaintext
					var letterCount = plainText.ToUpper().GroupBy(x => x).Select(y => new { y.Key, Count = y.Count() });

					double coefficiency = 0;
					// See this crypto stackexchange answer about Bhattacharyya coefficiency https://crypto.stackexchange.com/a/56477
					foreach (var letter in letterCount)
					{
						if (LetterFrequency.TryGetValue(letter.Key, out var frequency))
						{
							coefficiency += Math.Sqrt(frequency * letter.Count / plainText.Length);
						}
					}
					letterScores.Add(c, coefficiency);
				}

				// Get highest scoring key from letterScores
				var highestScore = letterScores.Values.Max();
				var highestScoreKey = letterScores.FirstOrDefault(x => x.Value == highestScore).Key;

				// Get the message by highest scoring key
				var highestScoreMessage = messages[highestScoreKey];

				messagesAll.Add(line, highestScoreMessage);
				letterScoresAll.Add(line, highestScore);
			}

			var totalHighestScore = letterScoresAll.Values.Max();
			var totalHighestScoreKey = letterScoresAll.FirstOrDefault(x => x.Value == totalHighestScore).Key;
			var totalHighestScoreMessage = messagesAll[totalHighestScoreKey];

			var answer = $"Highest scoring key: {totalHighestScoreKey} and decrypted message is: {totalHighestScoreMessage}";

			return answer;
        }

		// Challenge 5: Implementing repeating-key XOR
		public static bool Challenge5()
        {
			var buffer = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
			var key = "ICE";
			var keyIndex = 0;
			var bytesBuffer = Encoding.ASCII.GetBytes(buffer);
			var bufferSize = bytesBuffer.Length;
			byte[] xoredBuffer = new byte[bufferSize];

			// Looping through all the bytes
            for (int a = 0; a < bytesBuffer.Length; a++)
            {
				// Looping through the chars in key
				for (int i = 0; i < key.Length+1; i++)
				{
					if (keyIndex >= key.Length)
					{
						keyIndex = 0;
					}

					xoredBuffer[a] = (byte)(bytesBuffer[a] ^ key[keyIndex]);
					keyIndex++;
				}
			}            
			var hexString = Convert.ToHexString(xoredBuffer).ToLower();
			var expectedResult = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

			return hexString == expectedResult;
        }

		// Challenge 6: 
		public static string Challenge6()
        {

			return "";
        }













		// Frequency dictionary for letters used in English
		// Frequencies for letters here: http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
		// Added empty space to get better results, found the probability here: https://www.researchgate.net/figure/Probability-of-characters-in-English-The-SPACE-character-represented-by-has-the_fig2_47518347
		private static readonly Dictionary<char, double> LetterFrequency = new Dictionary<char, double>()
			{
				{'E', 12.02}, {'T', 9.10}, {'A', 8.12}, {'O', 7.68}, {'I', 7.31}, {'N', 6.95},
				{'S', 6.28}, {'R', 6.02}, {'H', 5.92}, {'D', 4.32}, {'L', 3.98}, {'U', 2.88},
				{'C', 2.71}, {'M', 2.61}, {'F', 2.30}, {'Y', 2.11}, {'W', 2.09}, {'G', 2.03},
				{'P', 1.82}, {'B', 1.49}, {'V', 1.11}, {'K', 0.69}, {'X', 0.17}, {'Q', 0.11},
				{'J', 0.10}, {'Z', 0.07}, {' ', 20.00}
			};
	}
}
