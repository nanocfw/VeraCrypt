/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Encryption_EncryptionAlgorithm
#define TC_HEADER_Encryption_EncryptionAlgorithm

#include "Platform/Platform.h"
#include "Cipher.h"
#include "EncryptionMode.h"

namespace VeraCrypt
{
	class EncryptionAlgorithm;
	typedef list < shared_ptr <EncryptionAlgorithm> > EncryptionAlgorithmList;

	class EncryptionAlgorithm
	{
	public:
		virtual ~EncryptionAlgorithm ();

		virtual byte *Decrypt (byte *data, uint64 length, uint64 *length_dec) const;
		virtual void Decrypt (BufferPtr *data) const;
		virtual byte *DecryptSectors (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize, uint64 *length_dec) const;
		virtual byte *Encrypt (byte *data, uint64 length, uint64 *length_enc) const;
		virtual void Encrypt (BufferPtr *data) const;
		virtual byte *EncryptSectors (byte *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize, uint64 *length_enc) const;
		static EncryptionAlgorithmList GetAvailableAlgorithms ();
		virtual const CipherList &GetCiphers () const { return Ciphers; }
		virtual shared_ptr <EncryptionAlgorithm> GetNew () const = 0;
		virtual size_t GetMaxBlockSize () const;
		virtual size_t GetMinBlockSize () const;
		static size_t GetLargestKeySize (const EncryptionAlgorithmList &algorithms);
		virtual size_t GetKeySize () const;
		virtual shared_ptr <EncryptionMode> GetMode () const;
		virtual wstring GetName (bool forGuiDisplay = false) const;
		bool IsDeprecated () const { return Deprecated; }
		virtual bool IsModeSupported (const EncryptionMode &mode) const;
		virtual bool IsModeSupported (const shared_ptr <EncryptionMode> mode) const;
		virtual void SetKey (const ConstBufferPtr &key);
		virtual void SetMode (shared_ptr <EncryptionMode> mode);
		bool IsSGX() {return FIsSGX; };
		int DefaultBytesAddSGX() {if(FIsSGX) return 560; return 0;}

	protected:
		EncryptionAlgorithm ();

		void ValidateState () const;

		CipherList Ciphers;
		bool Deprecated;
		bool FIsSGX;
		shared_ptr <EncryptionMode> Mode;
		EncryptionModeList SupportedModes;

	private:
		EncryptionAlgorithm (const EncryptionAlgorithm &);
		EncryptionAlgorithm &operator= (const EncryptionAlgorithm &);
	};

#define TC_ENCRYPTION_ALGORITHM(NAME) \
	class NAME : public EncryptionAlgorithm \
	{ \
	public: \
		NAME (); \
		virtual ~NAME () { } \
\
		virtual shared_ptr <EncryptionAlgorithm> GetNew () const { return shared_ptr <EncryptionAlgorithm> (new NAME()); } \
\
	private: \
		NAME (const NAME &); \
		NAME &operator= (const NAME &); \
	}

	TC_ENCRYPTION_ALGORITHM (AES);
	TC_ENCRYPTION_ALGORITHM (AESTwofish);
	TC_ENCRYPTION_ALGORITHM (AESTwofishSerpent);
	TC_ENCRYPTION_ALGORITHM (Serpent);
	TC_ENCRYPTION_ALGORITHM (SerpentAES);
	TC_ENCRYPTION_ALGORITHM (Twofish);
	TC_ENCRYPTION_ALGORITHM (TwofishSerpent);
	TC_ENCRYPTION_ALGORITHM (SerpentTwofishAES);
	TC_ENCRYPTION_ALGORITHM (Camellia);
	TC_ENCRYPTION_ALGORITHM (GOST89);
	TC_ENCRYPTION_ALGORITHM (Kuznyechik);
	TC_ENCRYPTION_ALGORITHM (KuznyechikTwofish);
	TC_ENCRYPTION_ALGORITHM (KuznyechikAES);
	TC_ENCRYPTION_ALGORITHM (KuznyechikSerpentCamellia);
	TC_ENCRYPTION_ALGORITHM (CamelliaKuznyechik);
	TC_ENCRYPTION_ALGORITHM (CamelliaSerpent);
	TC_ENCRYPTION_ALGORITHM (SGX);

#undef TC_ENCRYPTION_ALGORITHM
}

#endif // TC_HEADER_Encryption_EncryptionAlgorithm
