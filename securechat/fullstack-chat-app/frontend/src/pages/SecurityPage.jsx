import { useState, useEffect } from 'react';
import { useEncryptionStore } from '../store/useEncryptionStore';
import { Copy, Eye, EyeOff, Key, Lock } from 'lucide-react';
import toast from 'react-hot-toast';

const SecurityPage = () => {
  const {
    hasKeys,
    isLoading,
    securitySettings,
    updateSecuritySettings,
    privateKey,
    publicKey,
    generateKeys,
  } = useEncryptionStore();

  const [showKeys, setShowKeys] = useState(false);
  const [copied, setCopied] = useState({ pub: false, priv: false });

  const handleSecuritySettingChange = async (setting, value) => {
    try {
      await updateSecuritySettings({ [setting]: value });
    } catch (error) {
      toast.error('Failed to update setting');
    }
  };

  const handleCopy = (type, value) => {
    navigator.clipboard.writeText(value);
    setCopied((prev) => ({ ...prev, [type]: true }));
    setTimeout(() => setCopied((prev) => ({ ...prev, [type]: false })), 1200);
  };
      
  const handleGenerateKeys = async () => {
    try {
      await generateKeys('ECC');
      toast.success('Encryption keys generated!');
    } catch (error) {
      toast.error('Failed to generate keys');
    }
  };

  return (
    <div className="min-h-screen bg-base-100 flex flex-col items-center justify-center">
      <div className="w-full max-w-lg p-6 space-y-8">
        {/* Key Status Card */}
        <div className="card bg-base-200 shadow-xl">
          <div className="card-body">
            <h2 className="card-title flex items-center gap-2 text-lg">
              <Key className="w-5 h-5 text-primary" /> Encryption Keys
            </h2>
            <div className="flex items-center gap-2 mt-2">
              <span className={`badge ${hasKeys ? 'badge-success' : 'badge-error'}`}>{hasKeys ? 'Keys Generated' : 'No Keys'}</span>
              <span className="text-xs text-base-content/60">(ECC, never shared)</span>
            </div>
              {!hasKeys && (
                <button 
                className="btn btn-primary btn-sm mt-4"
                  onClick={handleGenerateKeys}
                  disabled={isLoading}
                >
                  Generate Keys
                </button>
              )}
            <div className="mt-4">
                <button 
                className="btn btn-sm btn-outline flex items-center gap-2"
                onClick={() => setShowKeys((v) => !v)}
                disabled={!hasKeys}
                >
                {showKeys ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                {showKeys ? 'Hide Keys' : 'Show My Keys'}
                </button>
            </div>
            {showKeys && (
              <div className="mt-4 space-y-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold text-xs">Public Key</span>
                    <button
                      className="btn btn-xs btn-ghost"
                      onClick={() => handleCopy('pub', publicKey)}
                    >
                      <Copy className="w-3 h-3" />
                      {copied.pub ? 'Copied!' : 'Copy'}
                    </button>
          </div>
                  <textarea
                    className="textarea textarea-bordered w-full text-xs bg-zinc-900 text-zinc-100"
                    value={publicKey || ''}
                    readOnly
                    rows={2}
                  />
              </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold text-xs">Private Key</span>
              <button 
                      className="btn btn-xs btn-ghost"
                      onClick={() => handleCopy('priv', privateKey)}
              >
                      <Copy className="w-3 h-3" />
                      {copied.priv ? 'Copied!' : 'Copy'}
              </button>
                      </div>
                  <textarea
                    className="textarea textarea-bordered w-full text-xs bg-zinc-900 text-zinc-100"
                    value={privateKey || ''}
                    readOnly
                    rows={2}
                  />
                  </div>
                </div>
              )}
            </div>
        </div>
      </div>
    </div>
  );
};

export default SecurityPage;
