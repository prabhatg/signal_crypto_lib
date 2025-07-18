# Dart Binding Guide for Signal Protocol

This guide provides comprehensive documentation for using the Signal Protocol Dart bindings in Flutter applications. It covers FFI integration, API usage, and best practices for secure messaging implementation.

## 📋 Table of Contents

1. [Overview](#overview)
2. [FFI Setup](#ffi-setup)
3. [Core API Reference](#core-api-reference)
4. [Usage Examples](#usage-examples)
5. [Error Handling](#error-handling)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

## 🔍 Overview

The Signal Protocol Dart binding provides a high-level interface to the Rust cryptographic library, enabling secure end-to-end encrypted messaging in Flutter applications. The binding consists of three main layers:

1. **FFI Layer** (`signal_ffi.dart`) - Direct interface to Rust functions
2. **Service Layer** - High-level services for protocol operations
3. **Model Layer** - Dart data models for cryptographic objects

## ⚙️ FFI Setup

### Dependencies

Add these dependencies to your `pubspec.yaml`:

```yaml
dependencies:
  flutter:
    sdk: flutter
  ffi: ^2.1.0
  provider: ^6.1.1
  sqflite: ^2.3.0
  path: ^1.8.3

dev_dependencies:
  json_annotation: ^4.8.1
  json_serializable: ^6.7.1
  build_runner: ^2.4.7
```

### Library Loading

The FFI binding automatically loads the native library:

```dart
import 'package:ffi/ffi.dart';
import 'dart:ffi';
import 'dart:io';

class SignalFFI {
  static final DynamicLibrary _lib = _loadLibrary();
  
  static DynamicLibrary _loadLibrary() {
    if (Platform.isAndroid) {
      return DynamicLibrary.open('libsignal_crypto.so');
    } else if (Platform.isIOS) {
      return DynamicLibrary.process();
    } else if (Platform.isLinux || Platform.isMacOS) {
      return DynamicLibrary.open('libsignal_crypto.so');
    } else if (Platform.isWindows) {
      return DynamicLibrary.open('signal_crypto.dll');
    }
    throw UnsupportedError('Platform not supported');
  }
}
```

## 📚 Core API Reference

### SignalProtocolService

The main service for Signal Protocol operations.

#### Initialization

```dart
final signalService = SignalProtocolService();
await signalService.initialize();
```

#### Identity Management

```dart
// Generate identity keypair
final identity = await signalService.generateIdentityKeypair();

// Generate prekey bundle
final prekeyBundle = await signalService.generatePrekeyBundle(identity);
```

#### Session Management

```dart
// Establish session (X3DH)
final session = await signalService.establishSession(
  aliceIdentity,
  bobPrekeyBundle,
);

// Store session
await signalService.storeSession(sessionId, session);

// Load session
final loadedSession = signalService.getSession(sessionId);
```

#### Message Encryption/Decryption

```dart
// Encrypt message
final encryptedResult = await signalService.encryptMessage(
  sessionId,
  'Hello, secure world!',
);

// Decrypt message
final decryptedMessage = await signalService.decryptMessage(
  sessionId,
  encryptedResult['encrypted_message'],
);
```

### GroupManager

Service for managing group conversations.

#### Group Creation

```dart
final groupManager = GroupManager(signalService);

final group = await groupManager.createGroup(
  'My Secure Group',
  currentUserId,
  [
    GroupMember(
      memberId: 'user_alice',
      name: 'Alice',
      identityKey: aliceIdentityKey,
      identityKeyEd: aliceIdentityKeyEd,
      joinedAt: DateTime.now(),
    ),
  ],
);
```

#### Member Management

```dart
// Add member
await groupManager.addMember(groupId, newMember);

// Remove member
await groupManager.removeMember(groupId, memberId);

// Update group name
await groupManager.updateGroupName(groupId, 'New Group Name');
```

### MessageService

Service for handling encrypted messages.

#### Sending Messages

```dart
final messageService = MessageService(signalService, groupManager);

// Send group message
final message = await messageService.sendGroupMessage(
  groupId,
  'Hello everyone!',
  MessageType.text,
);

// Send direct message
final directMessage = await messageService.sendDirectMessage(
  recipientId,
  'Private message',
  MessageType.text,
);
```

#### Receiving Messages

```dart
// Receive group message
await messageService.receiveGroupMessage(groupMessage);

// Receive direct message
await messageService.receiveDirectMessage(encryptedMessage);
```

#### Message Management

```dart
// Mark as read
await messageService.markAsRead(messageId);

// Delete message
await messageService.deleteMessage(messageId);

// Clear conversation
await messageService.clearConversation(conversationId);
```

## 💡 Usage Examples

### Complete Setup Example

```dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'services/signal_protocol_service.dart';
import 'services/group_manager.dart';
import 'services/message_service.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => SignalProtocolService()),
        ChangeNotifierProvider(create: (_) => GroupManager()),
        ChangeNotifierProvider(create: (_) => MessageService()),
      ],
      child: MaterialApp(
        title: 'Secure Chat',
        home: ChatScreen(),
      ),
    );
  }
}
```

### Creating a Secure Chat

```dart
class ChatScreen extends StatefulWidget {
  @override
  _ChatScreenState createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  late SignalProtocolService _signalService;
  late GroupManager _groupManager;
  late MessageService _messageService;
  String? _currentUserId;

  @override
  void initState() {
    super.initState();
    _initializeServices();
  }

  Future<void> _initializeServices() async {
    _signalService = Provider.of<SignalProtocolService>(context, listen: false);
    _groupManager = Provider.of<GroupManager>(context, listen: false);
    _messageService = Provider.of<MessageService>(context, listen: false);

    // Initialize Signal Protocol
    await _signalService.initialize();
    
    // Generate user identity
    final identity = await _signalService.generateIdentityKeypair();
    _currentUserId = 'user_${DateTime.now().millisecondsSinceEpoch}';
    _messageService.setCurrentUser(_currentUserId!);

    setState(() {});
  }

  Future<void> _createGroup() async {
    final group = await _groupManager.createGroup(
      'My Group',
      _currentUserId!,
      [], // Start with empty group
    );
    
    // Send welcome message
    await _messageService.sendGroupMessage(
      group.groupId,
      'Welcome to the group!',
      MessageType.text,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Secure Chat')),
      body: Consumer3<SignalProtocolService, GroupManager, MessageService>(
        builder: (context, signal, groups, messages, child) {
          if (!signal.isInitialized) {
            return Center(child: CircularProgressIndicator());
          }

          return Column(
            children: [
              // Group list
              Expanded(
                child: ListView.builder(
                  itemCount: groups.groups.length,
                  itemBuilder: (context, index) {
                    final group = groups.groups[index];
                    final groupMessages = messages.getGroupMessages(group.groupId);
                    
                    return ListTile(
                      title: Text(group.name),
                      subtitle: Text('${group.members.length} members'),
                      trailing: Text('${groupMessages.length} messages'),
                      onTap: () => _openChat(group),
                    );
                  },
                ),
              ),
              
              // Create group button
              Padding(
                padding: EdgeInsets.all(16),
                child: ElevatedButton(
                  onPressed: _createGroup,
                  child: Text('Create Group'),
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  void _openChat(GroupSession group) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => GroupChatScreen(group: group),
      ),
    );
  }
}
```

### Group Chat Implementation

```dart
class GroupChatScreen extends StatefulWidget {
  final GroupSession group;

  const GroupChatScreen({Key? key, required this.group}) : super(key: key);

  @override
  _GroupChatScreenState createState() => _GroupChatScreenState();
}

class _GroupChatScreenState extends State<GroupChatScreen> {
  final TextEditingController _messageController = TextEditingController();
  late MessageService _messageService;

  @override
  void initState() {
    super.initState();
    _messageService = Provider.of<MessageService>(context, listen: false);
  }

  Future<void> _sendMessage() async {
    final text = _messageController.text.trim();
    if (text.isEmpty) return;

    await _messageService.sendGroupMessage(
      widget.group.groupId,
      text,
      MessageType.text,
    );

    _messageController.clear();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.group.name),
        actions: [
          IconButton(
            icon: Icon(Icons.group),
            onPressed: () => _showMemberList(),
          ),
        ],
      ),
      body: Column(
        children: [
          // Message list
          Expanded(
            child: Consumer<MessageService>(
              builder: (context, messageService, child) {
                final messages = messageService.getGroupMessages(widget.group.groupId);
                
                return ListView.builder(
                  itemCount: messages.length,
                  itemBuilder: (context, index) {
                    final message = messages[index];
                    final isMe = message.senderId == messageService.currentUserId;
                    
                    return Align(
                      alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
                      child: Container(
                        margin: EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                        padding: EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: isMe ? Colors.blue : Colors.grey[300],
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            if (!isMe)
                              Text(
                                message.senderId ?? 'Unknown',
                                style: TextStyle(
                                  fontWeight: FontWeight.bold,
                                  fontSize: 12,
                                ),
                              ),
                            Text(
                              message.content,
                              style: TextStyle(
                                color: isMe ? Colors.white : Colors.black,
                              ),
                            ),
                            Text(
                              _formatTime(message.timestamp),
                              style: TextStyle(
                                fontSize: 10,
                                color: isMe ? Colors.white70 : Colors.grey[600],
                              ),
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                );
              },
            ),
          ),
          
          // Message input
          Container(
            padding: EdgeInsets.all(16),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    decoration: InputDecoration(
                      hintText: 'Type a message...',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(24),
                      ),
                    ),
                    onSubmitted: (_) => _sendMessage(),
                  ),
                ),
                SizedBox(width: 8),
                FloatingActionButton(
                  mini: true,
                  onPressed: _sendMessage,
                  child: Icon(Icons.send),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showMemberList() {
    showModalBottomSheet(
      context: context,
      builder: (context) => Container(
        padding: EdgeInsets.all(16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'Group Members',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            SizedBox(height: 16),
            ...widget.group.members.map((member) => ListTile(
              leading: CircleAvatar(child: Text(member.name[0])),
              title: Text(member.name),
              subtitle: Text('Joined ${_formatDate(member.joinedAt)}'),
            )),
          ],
        ),
      ),
    );
  }

  String _formatTime(DateTime dateTime) {
    return '${dateTime.hour}:${dateTime.minute.toString().padLeft(2, '0')}';
  }

  String _formatDate(DateTime dateTime) {
    return '${dateTime.day}/${dateTime.month}/${dateTime.year}';
  }
}
```

## ⚠️ Error Handling

### FFI Error Handling

```dart
class SignalProtocolException implements Exception {
  final String message;
  final String? code;
  
  SignalProtocolException(this.message, [this.code]);
  
  @override
  String toString() => 'SignalProtocolException: $message${code != null ? ' ($code)' : ''}';
}

// In service methods
Future<IdentityKeyPair> generateIdentityKeypair() async {
  try {
    final result = SignalFFI.generateIdentityKeypair();
    if (!result['success']) {
      throw SignalProtocolException(
        result['error'] ?? 'Unknown error',
        result['code'],
      );
    }
    return IdentityKeyPair.fromJson(result['data']);
  } catch (e) {
    if (e is SignalProtocolException) rethrow;
    throw SignalProtocolException('Failed to generate identity keypair: $e');
  }
}
```

### Service Error Handling

```dart
// Wrap service calls with proper error handling
Future<void> _sendMessageSafely(String groupId, String content) async {
  try {
    await _messageService.sendGroupMessage(groupId, content, MessageType.text);
  } on SignalProtocolException catch (e) {
    _showError('Encryption failed: ${e.message}');
  } catch (e) {
    _showError('Failed to send message: $e');
  }
}

void _showError(String message) {
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text(message),
      backgroundColor: Colors.red,
    ),
  );
}
```

## 🔒 Best Practices

### Security Best Practices

1. **Key Management**
   ```dart
   // Always store keys securely
   // Never log or expose private keys
   // Use secure storage for persistent keys
   ```

2. **Session Management**
   ```dart
   // Regularly clean up old sessions
   // Implement session timeout
   // Handle session corruption gracefully
   ```

3. **Memory Management**
   ```dart
   // Clear sensitive data when done
   @override
   void dispose() {
     _messageController.dispose();
     // Clear any cached keys or sessions
     super.dispose();
   }
   ```

### Performance Best Practices

1. **Async Operations**
   ```dart
   // Always use async/await for crypto operations
   // Don't block the UI thread
   // Show loading indicators for long operations
   ```

2. **State Management**
   ```dart
   // Use Provider for reactive updates
   // Minimize unnecessary rebuilds
   // Cache frequently accessed data
   ```

3. **Memory Usage**
   ```dart
   // Limit message history in memory
   // Use pagination for large conversations
   // Implement proper cleanup
   ```

### Code Organization

1. **Separation of Concerns**
   ```
   services/          # Business logic
   models/           # Data models
   screens/          # UI components
   utils/            # Helper functions
   ```

2. **Error Boundaries**
   ```dart
   // Wrap each major feature in try-catch
   // Provide meaningful error messages
   // Implement fallback mechanisms
   ```

## 🔧 Troubleshooting

### Common Issues

1. **Library Loading Fails**
   ```
   Error: DynamicLibrary.open failed
   Solution: Ensure the native library is properly built and included
   ```

2. **FFI Type Errors**
   ```
   Error: Invalid argument type
   Solution: Check FFI type definitions match Rust signatures
   ```

3. **JSON Parsing Errors**
   ```
   Error: FormatException
   Solution: Validate JSON structure from FFI calls
   ```

### Debug Mode

Enable debug logging:

```dart
class SignalProtocolService extends ChangeNotifier {
  static const bool _debugMode = true;
  
  void _debugLog(String message) {
    if (_debugMode) {
      print('[SignalProtocol] $message');
    }
  }
}
```

### Testing

```dart
// Unit tests for services
void main() {
  group('SignalProtocolService', () {
    late SignalProtocolService service;
    
    setUp(() {
      service = SignalProtocolService();
    });
    
    test('should generate identity keypair', () async {
      await service.initialize();
      final identity = await service.generateIdentityKeypair();
      expect(identity.dhPublic.length, equals(32));
      expect(identity.dhPrivate.length, equals(32));
    });
  });
}
```

## 📖 Additional Resources

- [Signal Protocol Specification](https://signal.org/docs/)
- [Flutter FFI Documentation](https://flutter.dev/docs/development/platform-integration/c-interop)
- [Dart FFI Package](https://pub.dev/packages/ffi)
- [Provider State Management](https://pub.dev/packages/provider)

---

This guide provides the foundation for integrating Signal Protocol into Flutter applications. For production use, ensure proper security auditing and compliance with relevant regulations.