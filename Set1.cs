using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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

			// Loop through chars and add to messages-dictionary the keys and values that result from XOR-ing
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
			string sourceFile = "4.txt";
			IEnumerable<string> fileLines = File.ReadLines(sourceFile);
			string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789 "; // There is better solution for this, but I couldn't get it working so this is fine.
			Dictionary<string, string> messagesAll = new Dictionary<string, string>();
			Dictionary<string, double> letterScoresAll = new Dictionary<string, double>();

			// Loop through the lines extracted from the file
			foreach (var line in fileLines)
			{
				Dictionary<char, string> messages = new Dictionary<char, string>();
				Dictionary<char, double> letterScores = new Dictionary<char, double>();

				var bytesBuffer = Convert.FromHexString(line);
				var bufferSize = bytesBuffer.Length;

				// Loop through chars and add to messages-dictionary the keys and values that result from XOR-ing
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

			//Get the highest scoring key from letterScoresAll
			var totalHighestScore = letterScoresAll.Values.Max();
			var totalHighestScoreKey = letterScoresAll.FirstOrDefault(x => x.Value == totalHighestScore).Key;

			// Get the message by the highest overall score
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
				for (int i = 0; i < key.Length + 1; i++)
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

		// Challenge 6: Break repeating-key XOR
		public static string Challenge6()
		{
			// Testing if our HammingDistance works as needed
			var buffer1 = "this is a test";
			var buffer2 = "wokka wokka!!!";
			var bytesBuffer1 = Encoding.ASCII.GetBytes(buffer1);
			var bytesBuffer2 = Encoding.ASCII.GetBytes(buffer2);

			var hammingDistTest = HammingDistance(bytesBuffer1, bytesBuffer2);

			if (hammingDistTest != 37)
			{
				return "HammingDistance not working!";
			}

			// Let's start the challenge by retrieving the data from txt-file and setting keysize information
			var minKeySize = 2;
			var maxKeySize = 40;

			string sourceFile = "6.txt";
			IEnumerable<string> fileLines = File.ReadLines(sourceFile);
			var allLines = string.Join("", fileLines);
			var bytes = Convert.FromBase64String(allLines);

			// Now we get the keySize
			var keySize = GetKeySize(bytes, minKeySize, maxKeySize);

			var blocksAmount = bytes.Length / keySize;
			var blocksRemainder = bytes.Length % keySize;
			List<byte[]> blocks = new List<byte[]>();

			// Add blocks by looping
			for (int i = 0; i < blocksAmount; i++)
			{
				blocks.Add(bytes[(i * keySize)..((i * keySize) + keySize)]);
			}

			// If there is remainder, add final block
			if (blocksRemainder != 0)
			{
				blocks.Add(bytes[(bytes.Length - blocksRemainder)..bytes.Length]);
			}

			// Then we transpose the blocks
			List<byte[]> transposedBlocks = new List<byte[]>();
			for (int i = 0; i < keySize; i++)
			{
				List<byte> transposedBlock = new List<byte>();
				foreach (byte[] block in blocks)
				{
					try
					{
						transposedBlock.Add(block[i]);
					}
					// We got IndexOutOfRangeException, because of the last block being smaller than keySize. We break the loop before that
					catch (IndexOutOfRangeException)
					{
						break;
					}
				}
				// We add transposed blocks to transposedBlocks as an array
				transposedBlocks.Add(transposedBlock.ToArray());
			}

			// Next we brute-force each block as if they were single-character XOR.

			// There is better solution for this, but I couldn't get it working so this is fine. Also added few punctuation marks, since after testing it seemed to give better results
			string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789 .,?!:;'()[]{}-/";
			List<byte> keyBytes = new List<byte>();
			foreach (var block in transposedBlocks)
			{
				Dictionary<char, string> messages = new Dictionary<char, string>();
				Dictionary<char, double> letterScores = new Dictionary<char, double>();
				var bufferSize = block.Length;

				// Loop through the chars to use
				foreach (var c in chars)
				{
					byte[] xoredBuffer = new byte[bufferSize];

					for (int i = 0; i < bufferSize; i++)
					{
						xoredBuffer[i] = (byte)(block[i] ^ c);
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

				keyBytes.Add((byte)highestScoreKey);
			}
			// Key for decrypting
			byte[] key = keyBytes.ToArray();
			Console.WriteLine(Encoding.UTF8.GetString(key));

			// Now we want to decrypt the original ciphertext
			var keyIndex = 0;
			var bytesSize = bytes.Length;
			byte[] xoredBytes = new byte[bytesSize];

			// Looping through all the bytes
			for (int a = 0; a < xoredBytes.Length; a++)
			{
				// Looping through the chars in key
				for (int i = 0; i < key.Length + 1; i++)
				{
					if (keyIndex >= key.Length)
					{
						keyIndex = 0;
					}

					xoredBytes[a] = (byte)(bytes[a] ^ key[keyIndex]);
					keyIndex++;
				}
			}

			var hexString = Convert.ToHexString(xoredBytes).ToLower();

			var plainTextResult = Encoding.UTF8.GetString(xoredBytes);

			// Finally print out the answer
			var answer = "Message: \n" + plainTextResult;
			return answer;
		}

		// Challenge 7: AES in ECB mode
		public static string Challenge7()
		{
			// Getting the source text and making one long string of it, and then convert to bytes
			string sourceFile = "7.txt";
			IEnumerable<string> fileLines = File.ReadLines(sourceFile);
			var lines = "";
			
			foreach (string line in fileLines)
			{
				lines += line;
			}
			var bytes = Convert.FromBase64String(lines);

			// Let's get started with decryption by creating decryptor
			var key = "YELLOW SUBMARINE";
			var keyBytes = Encoding.ASCII.GetBytes(key);
			var aes = new AesManaged
			{
				Key = keyBytes,
				Mode = CipherMode.ECB,
			};
			var decryptor = aes.CreateDecryptor();

			// Finally we use the decryptor to transform the the bytes
			var resultBytes = decryptor.TransformFinalBlock(bytes, 0, bytes.Length);

			// Get the plaintext result and print it out to console
			string result = Encoding.ASCII.GetString(resultBytes);
			return "Message: \n" + result;
		}

		//Challenge 8: Detect AES in ECB mode
		public static string Challenge8()
		{
			// Let's get the sourcefile and convert the lines to bytes
			string sourceFile = "8.txt";
			IEnumerable<string> fileLines = File.ReadLines(sourceFile);
			
			// List for lines that contain ECB
			List<string> ecbLines = new List<string>();

			foreach (string line in fileLines)
			{
				var lineBytes = Convert.FromHexString(line);
				var hasEcb = false;
				List<byte[]> blockBytes = new List<byte[]>();

				// We know from the Challenge that there will be 16 byte ciphertext, so lets make those blocks
				for (int i = 0; i < lineBytes.Length; i += 16)
				{
					var block = lineBytes[i..(i + 16)];
					blockBytes.Add(block);
				}

				// Now we loop through the blocks
				for (int i = 0; i < blockBytes.Count; i++)
				{
					// And another loop so we got something to compare against
					for (int j = 0; j < blockBytes.Count; j++)
					{
						var block1 = blockBytes[i];
						var block2 = blockBytes[j];

						// We compare if the blocks are equal, but not the exact same index, if they are equal we add them to the list and assume the line has ecb mode encryption
						if (i != j && block1.SequenceEqual(block2))
						{
							hasEcb = true;					
						}
					}
				}
				if (hasEcb)
				{
					ecbLines.Add(line);
				}
			}

			// Finally print out the answer
			var answer = "EcbLine(s): ";
			foreach (var line in ecbLines)
			{
				answer += line + "\n";
			}		

			return answer;
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

		// Calculate hammingdistance: amount of differing bits between two byte arrays
		private static int HammingDistance(byte[] bytes1, byte[] bytes2)
		{
			if (bytes1.Length != bytes2.Length)
			{
				return -1;
			}

			var hammingDistance = 0;
			BitArray bitArray1 = new BitArray(bytes1);
			BitArray bitArray2 = new BitArray(bytes2);

			// XOR each byte in buffer and add it to the xoredBuffer bytearray
			for (int i = 0; i < bitArray1.Length; i++)
			{
				var xored = (bitArray1[i] ^ bitArray2[i]);

				if (xored != false)
				{
					hammingDistance++;
				}
			}

			return hammingDistance;
		}

		private static int GetKeySize(byte[] bytes, int minKeySize, int maxKeySize)
		{

			double ksScore = 0.0;
			Dictionary<int, double> keyScores = new Dictionary<int, double>();

			// Let's loop through key sizes
			for (int i = minKeySize; i < maxKeySize; i++)
			{
				int remainder = bytes.Length % i;
				double avgHammingDistance = 0.0;
				int counter = 0;

				// Next we loop through the bytes and create blocks of it to calculate HammingDistance, we double the increment because we need 2 blocks for HammingDistance
				for (int a = 0; a < (bytes.Length - remainder - a); a += (i*2))
				{
					byte[] bytesBlock1 = bytes[a..(a + i)];
					byte[] bytesBlock2 = bytes[(a + i)..(a + (i * 2))];

					double hammingDistance = HammingDistance(bytesBlock1, bytesBlock2);
					avgHammingDistance += hammingDistance;
					counter++;
				}

				// Let's now calculate the average with counter and normalize it
				avgHammingDistance = avgHammingDistance / counter;
				double normalizedAvgHammingDistance = avgHammingDistance / (double)i;
				keyScores.Add(i, normalizedAvgHammingDistance);
			}

			// Let's get the smallest score on keyScores list as a key of choice
			var lowestScore = keyScores.Values.Min();
			var keySize = keyScores.FirstOrDefault(x => x.Value == lowestScore).Key;

			return keySize;
		}
	}
}
