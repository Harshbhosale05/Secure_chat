import { useChatStore } from "../store/useChatStore";
import { useEffect, useRef, useState } from "react";

import ChatHeader from "./ChatHeader";
import MessageInput from "./MessageInput";
import MessageSkeleton from "./skeletons/MessageSkeleton";
import { useAuthStore } from "../store/useAuthStore";
import { formatMessageTime } from "../lib/utils";
import { useEncryptionStore } from "../store/useEncryptionStore";

const Watermark = () => {
	const { authUser } = useAuthStore();
	if (!authUser) return null;

	const watermarkText = `${authUser.email} - ${authUser._id}`;
	return (
		<div className='absolute inset-0 -z-10 overflow-hidden pointer-events-none'>
			<div
				className='absolute -top-1/4 -left-1/4 w-[200%] h-[200%]
        flex flex-wrap gap-4 content-center
        opacity-5'
			>
				{Array.from({ length: 500 }).map((_, i) => (
					<div
						key={i}
						className='text-5xl font-bold text-gray-500 whitespace-nowrap -rotate-[30deg]'
					>
						{watermarkText}
					</div>
				))}
			</div>
		</div>
	);
};

const ChatContainer = () => {
  const {
    messages,
    getMessages,
    isMessagesLoading,
    selectedUser,
    subscribeToMessages,
    unsubscribeFromMessages,
    setMessages,
  } = useChatStore();
  const { authUser } = useAuthStore();
  const messageEndRef = useRef(null);
  const { privateKey } = useEncryptionStore();
  const [decryptedMessages, setDecryptedMessages] = useState({});
  const [vanishingIds, setVanishingIds] = useState([]);

  useEffect(() => {
    getMessages(selectedUser._id);

    subscribeToMessages();

    return () => unsubscribeFromMessages();
  }, [selectedUser._id, getMessages, subscribeToMessages, unsubscribeFromMessages]);

  useEffect(() => {
    if (messageEndRef.current && messages) {
      messageEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  useEffect(() => {
    // Set up timers for messages with expiresAt
    const now = new Date();
    const timers = messages
      .filter(msg => msg.expiresAt && new Date(msg.expiresAt) > now)
      .map(msg => {
        const timeout = new Date(msg.expiresAt) - now;
        return setTimeout(() => {
          setVanishingIds(ids => [...ids, msg._id]);
          setTimeout(() => {
            setMessages(current => current.filter(m => m._id !== msg._id));
            setVanishingIds(ids => ids.filter(id => id !== msg._id));
          }, 800); // 800ms fade-out
        }, timeout);
      });
    return () => timers.forEach(clearTimeout);
  }, [messages, setMessages]);

  useEffect(() => {
    // Decrypt all messages asynchronously
    async function decryptAll() {
      const results = {};
      for (const message of messages) {
        try {
          let senderPublicKey = message.senderPublicKey;
          if (!senderPublicKey) {
            if (message.senderId === authUser._id) {
              senderPublicKey = authUser.publicKey;
            } else {
              senderPublicKey = selectedUser.publicKey;
            }
          }
          if (message.encryptedContent && senderPublicKey && privateKey) {
            const decrypted = await window.clientEncryption.decryptMessageHybrid(
              JSON.parse(message.encryptedContent),
              senderPublicKey,
              privateKey
            );
            results[message._id] = decrypted;
          }
        } catch (err) {
          results[message._id] = "[Unable to decrypt]";
        }
      }
      setDecryptedMessages(results);
    }
    decryptAll();
  }, [messages, privateKey, authUser, selectedUser]);

  if (isMessagesLoading) {
    return (
      <div className="flex-1 flex flex-col overflow-auto">
        <ChatHeader />
        <MessageSkeleton />
        <MessageInput />
      </div>
    );
  }

  return (
    <div className='flex-1 flex flex-col'>
			<Watermark />
      <ChatHeader />
      <div className='flex-1 overflow-auto p-4'>
        {messages.map((message) => {
          // Use decryptedMessages state
          let displayText = "";
          if (message.senderId === authUser._id) {
            // Show original text for sender if available before reload
            displayText = message.tempText || "[You sent a message]";
          } else {
            displayText = decryptedMessages[message._id] || "[Unable to decrypt]";
          }
          return (
            <div
              key={message._id}
              className={`chat ${message.senderId === authUser._id ? "chat-end" : "chat-start"} ${vanishingIds.includes(message._id) ? "opacity-0 transition-opacity duration-700" : "opacity-100 transition-opacity duration-700"}`}
              ref={messageEndRef}
            >
              <div className="chat-image avatar">
                <div className="size-10 rounded-full border">
                  <img
                    src={
                      message.senderId === authUser._id
                        ? authUser.profilePic || "/avatar.png"
                        : selectedUser.profilePic || "/avatar.png"
                    }
                    alt="profile pic"
                  />
                </div>
              </div>
              <div className="chat-header mb-1">
                <time className="text-xs opacity-50 ml-1">
                  {formatMessageTime(message.createdAt)}
                </time>
              </div>
              <div className="chat-bubble flex flex-col">
                {message.image && (
                  <img
                    src={message.image}
                    alt="Attachment"
                    className="sm:max-w-[200px] rounded-md mb-2"
                  />
                )}
                {/* Show displayText */}
                {displayText && <p>{displayText}</p>}
              </div>
            </div>
          );
        })}
      </div>

      <MessageInput />
    </div>
  );
};
export default ChatContainer;
