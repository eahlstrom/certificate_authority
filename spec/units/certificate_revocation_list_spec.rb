describe CertificateAuthority::CertificateRevocationList do
  before(:each) do
    @crl = CertificateAuthority::CertificateRevocationList.new(crl_number: 1337)

    @root_certificate = CertificateAuthority::Certificate.new
    @root_certificate.signing_entity = true
    @root_certificate.subject.common_name = "CRL Root"
    @root_certificate.key_material.generate_key(768)
    @root_certificate.serial_number.number = 1
    @root_certificate.sign!

    @certificate = CertificateAuthority::Certificate.new
    @certificate.key_material.generate_key(768)
    @certificate.subject.common_name = "http://bogusSite.com"
    @certificate.parent = @root_certificate
    @certificate.serial_number.number = 2
    @certificate.sign!

    @serial_number = CertificateAuthority::SerialNumber.new
    @serial_number.revoke!('superseded', Time.now)
    @serial_number.number = 5

    @crl.parent = @root_certificate
    @certificate.revoke!('keyCompromise', Time.now)
  end

  it "should accept a list of certificates" do
    @crl << @certificate
  end

  it "should have a 'parent' that will be responsible for signing" do
    @crl.parent = @root_certificate
    expect(@crl.parent).not_to be_nil
  end

  it "should raise an error if you try and sign a CRL without attaching a parent" do
    @crl.parent = nil
    expect { @crl.sign! }.to raise_error(RuntimeError)
  end

  it "should be able to generate a proper CRL" do
    @crl << @certificate
    expect {@crl.to_pem}.to raise_error(RuntimeError)
    @crl.parent = @root_certificate
    @crl.sign!
    expect(@crl.to_pem).not_to be_nil
    x509crl = OpenSSL::X509::CRL.new(@crl.to_pem)
    expect(x509crl).not_to be_nil
    expect(x509crl.extensions.size).to eq(1), "found no x509v3 extensions!?"
    expect(x509crl.extensions[0].oid).to eq "crlNumber"
    expect(x509crl.extensions[0].value).to eq "1337"
    expect(x509crl.revoked.size).to eq(1), "no revoked certs found"
    expect(x509crl.revoked[0].extensions.size).to eq(1), "no revokation extension found"
    expect(x509crl.revoked[0].extensions[0].oid).to eq("CRLReason")
    expect(x509crl.revoked[0].extensions[0].value).to match(/(keyCompromise|Key Compromise)/)
  end

  it "should not include CRLReason for an unspecified reason code" do
    @certificate.revoke!('unspecified')
    expect(@certificate.revokation_reason).to eq('unspecified')
    @crl << @certificate
    expect {@crl.to_pem}.to raise_error(RuntimeError)
    @crl.parent = @root_certificate
    @crl.sign!
    expect(@crl.to_pem).not_to be_nil
    x509crl = OpenSSL::X509::CRL.new(@crl.to_pem)
    expect(x509crl).not_to be_nil
    expect(x509crl.extensions.size).to eq(1), "found no x509v3 extensions!?"
    expect(x509crl.revoked[0].extensions.size).to eq(0), "revokation extension found for unspecifed reason code"
  end

  it "should be able to mix Certificates and SerialNumbers for convenience" do
    @crl << @certificate
    @crl << @serial_number
    @crl.parent = @root_certificate
    @crl.sign!
    openssl_csr = OpenSSL::X509::CRL.new(@crl.to_pem)
    expect(openssl_csr.revoked.size).to eq(2)
  end

  it "should have the correct number of entities" do
    @crl << @certificate
    @crl.parent = @root_certificate
    @crl.sign!
    openssl_clr = OpenSSL::X509::CRL.new(@crl.to_pem)
    expect(openssl_clr.revoked).to be_a(Array)
    expect(openssl_clr.revoked.size).to eq(1)
  end

  it "should have the serial numbers of revoked entities" do
    @crl << @certificate
    @crl << @serial_number
    @crl.parent = @root_certificate
    @crl.sign!
    openssl_clr = OpenSSL::X509::CRL.new(@crl.to_pem)
    expect(openssl_clr.revoked).to be_a(Array)
    expect(openssl_clr.revoked.first.serial).to eq(@certificate.serial_number.number)
    expect(openssl_clr.revoked.last.serial).to eq(@serial_number.number)
  end

  it "should be valid according to OpenSSL and signer" do
    @crl << @certificate
    @crl.parent = @root_certificate
    @crl.sign!
    openssl_clr = OpenSSL::X509::CRL.new(@crl.to_pem)
    openssl_root = OpenSSL::X509::Certificate.new(@root_certificate.to_pem)
    expect(openssl_clr.verify(openssl_root.public_key)).to be_truthy
  end

  describe "Digests" do
    it "should use SHA512 by default" do
      @crl << @certificate
      @crl.parent = @root_certificate
      @crl.sign!
      openssl_clr = OpenSSL::X509::CRL.new(@crl.to_pem)
      expect(openssl_clr.signature_algorithm).to eq("sha512WithRSAEncryption")
    end

    it "should support alternate digests supported by OpenSSL" do
      @crl << @certificate
      @crl.parent = @root_certificate
      @crl.sign!({"digest" => "SHA1"})
      openssl_clr = OpenSSL::X509::CRL.new(@crl.to_pem)
      expect(openssl_clr.signature_algorithm).to eq("sha1WithRSAEncryption")
    end
  end

  describe "Next update" do
    it "should be able to set a 'next_update' value" do
      @crl.next_update = (60 * 60 * 10) # 10 Hours
      expect(@crl.next_update).not_to be_nil
    end

    it "should throw an error if we try and sign up with a negative next_update" do
      @crl.sign!
      @crl.next_update = - (60 * 60 * 10)
      expect{@crl.sign!}.to raise_error(RuntimeError)
    end
  end
end
