import React, { useState, useEffect, useRef } from 'react';
import {
  SafeAreaView,
  View,
  Text,
  Button,
  FlatList,
  TouchableOpacity,
  PermissionsAndroid,
  Platform,
  Alert,
  StyleSheet,
  ActivityIndicator,
} from 'react-native';
import { BleManager } from 'react-native-ble-plx';
import nacl from 'tweetnacl';
import { sha256 } from 'crypto-js';
import AES from 'react-native-aes-crypto';
import base64 from 'react-native-base64';
import RNFS from 'react-native-fs'; // For saving files

// Sample UUIDs for BLE service and characteristics (same as sender)
const SERVICE_UUID = '12345678-1234-5678-1234-56789abcdef0';
const HANDSHAKE_CHAR_UUID = '12345678-1234-5678-1234-56789abcdef1';
const TRANSFER_CHAR_UUID = '12345678-1234-5678-1234-56789abcdef2';

const App = () => {
  const manager = useRef(new BleManager()).current;

  // State variables
  const [isAdvertising, setIsAdvertising] = useState(false);
  const [connectedDevice, setConnectedDevice] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('Not advertising');
  const [receivedFileName, setReceivedFileName] = useState(null);
  const [transferProgress, setTransferProgress] = useState(0);
  const [error, setError] = useState(null);

  // Cryptographic keys and shared secret
  const ephemeralKeyPair = useRef(null);
  const sharedSecret = useRef(null);
  const aesKey = useRef(null);

  // BLE characteristics
  const handshakeChar = useRef(null);
  const transferChar = useRef(null);

  // Received chunks
  const receivedChunks = useRef([]);
  const totalChunks = useRef(0);

  // Permissions request for Android
  const requestPermissions = async () => {
    if (Platform.OS === 'android') {
      try {
        const granted = await PermissionsAndroid.requestMultiple([
          PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_ADVERTISE,
        ]);
        const allGranted = Object.values(granted).every(
          (status) => status === PermissionsAndroid.RESULTS.GRANTED
        );
        if (!allGranted) {
          Alert.alert('Permissions required', 'Bluetooth and Location permissions are required.');
          return false;
        }
        return true;
      } catch (err) {
        setError('Permission request error: ' + err.message);
        return false;
      }
    }
    // iOS permissions handled by react-native-ble-plx internally
    return true;
  };

  // Start advertising BLE service
  const startAdvertising = async () => {
    setError(null);
    const permission = await requestPermissions();
    if (!permission) return;

    setIsAdvertising(true);
    setConnectionStatus('Advertising...');

    try {
      // Add service with characteristics
      await manager.addListener('stateChange', (state) => {
        if (state === 'PoweredOn') {
          manager.startAdvertising({
            localName: 'BLE File Receiver',
            serviceUUIDs: [SERVICE_UUID],
          });
        }
      });

      // Listen for connections
      manager.onDeviceDisconnected((error, device) => {
        if (error) {
          setError('Disconnect error: ' + error.message);
        }
        setConnectedDevice(null);
        setConnectionStatus('Disconnected');
        setReceivedFileName(null);
        setTransferProgress(0);
        receivedChunks.current = [];
        totalChunks.current = 0;
      });

      manager.onDeviceConnected(async (error, device) => {
        if (error) {
          setError('Connection error: ' + error.message);
          return;
        }
        setConnectedDevice(device);
        setConnectionStatus('Connected');

        // Discover services and characteristics
        await device.discoverAllServicesAndCharacteristics();

        const services = await device.services();
        let handshakeCharacteristic = null;
        let transferCharacteristic = null;

        for (const service of services) {
          if (service.uuid.toLowerCase() === SERVICE_UUID.toLowerCase()) {
            const characteristics = await service.characteristics();
            for (const char of characteristics) {
              if (char.uuid.toLowerCase() === HANDSHAKE_CHAR_UUID.toLowerCase()) {
                handshakeCharacteristic = char;
              } else if (char.uuid.toLowerCase() === TRANSFER_CHAR_UUID.toLowerCase()) {
                transferCharacteristic = char;
              }
            }
          }
        }

        if (!handshakeCharacteristic || !transferCharacteristic) {
          setError('Required BLE characteristics not found.');
          return;
        }

        handshakeChar.current = handshakeCharacteristic;
        transferChar.current = transferCharacteristic;

        // Perform key exchange
        await performKeyExchange();

        // Start listening for file chunks
        await transferChar.current.monitor(async (error, characteristic) => {
          if (error) {
            setError('Notification error: ' + error.message);
            return;
          }
          if (characteristic?.value) {
            const encryptedChunkBase64 = base64.decode(characteristic.value);
            await processReceivedChunk(encryptedChunkBase64);
          }
        });
      });

    } catch (err) {
      setError('Advertising error: ' + err.message);
      setIsAdvertising(false);
      setConnectionStatus('Not advertising');
    }
  };

  // Stop advertising
  const stopAdvertising = async () => {
    try {
      await manager.stopAdvertising();
      setIsAdvertising(false);
      setConnectionStatus('Not advertising');
    } catch (err) {
      setError('Stop advertising error: ' + err.message);
    }
  };

  // Generate ephemeral Curve25519 key pair
  const generateEphemeralKeyPair = () => {
    const keyPair = nacl.box.keyPair();
    return keyPair;
  };

  // Perform key exchange over handshake characteristic
  const performKeyExchange = async () => {
    try {
      ephemeralKeyPair.current = generateEphemeralKeyPair();

      // Read sender's public key
      const senderPubChar = await handshakeChar.current.read();
      if (!senderPubChar?.value) {
        throw new Error('Failed to read sender public key');
      }
      const senderPubKeyStr = base64.decode(senderPubChar.value);
      const senderPubKeyUint8 = Uint8Array.from(senderPubKeyStr, (c) => c.charCodeAt(0));

      // Write our public key
      const pubKeyStr = base64.encode(String.fromCharCode(...ephemeralKeyPair.current.publicKey));
      await handshakeChar.current.writeWithResponse(pubKeyStr);

      // Derive shared secret
      sharedSecret.current = nacl.box.before(senderPubKeyUint8, ephemeralKeyPair.current.secretKey);

      // Derive AES key
      await deriveAESKey(sharedSecret.current);

    } catch (err) {
      setError('Key exchange error: ' + err.message);
    }
  };

  // Derive AES-GCM key from shared secret
  const deriveAESKey = async (sharedSecretUint8) => {
    try {
      const sharedSecretHex = Buffer.from(sharedSecretUint8).toString('hex');
      const hash = sha256(sharedSecretHex).toString();
      const aesKeyHex = hash.slice(0, 64);
      aesKey.current = aesKeyHex;
    } catch (err) {
      setError('AES key derivation error: ' + err.message);
    }
  };

  // Process received encrypted chunk
  const processReceivedChunk = async (encryptedChunkBase64) => {
    try {
      // Decrypt chunk
      const decryptedChunk = await decryptChunk(encryptedChunkBase64);
      receivedChunks.current.push(decryptedChunk);

      // Send ACK
      await transferChar.current.writeWithoutResponse(base64.encode('ACK'));

      // Update progress (assuming we know total chunks somehow, or estimate)
      setTransferProgress(Math.round((receivedChunks.current.length / totalChunks.current) * 100));

      // If this is the last chunk, assemble and save file
      if (receivedChunks.current.length === totalChunks.current) {
        await assembleAndSaveFile();
      }

    } catch (err) {
      setError('Chunk processing error: ' + err.message);
    }
  };

  // Decrypt chunk with AES-GCM
  const decryptChunk = async (encryptedChunkBase64) => {
    try {
      // Assume encryptedChunkBase64 is iv + cipher
      const encryptedData = base64.decode(encryptedChunkBase64);
      const iv = encryptedData.slice(0, 12); // 12 bytes IV
      const cipher = encryptedData.slice(12);

      const decrypted = await AES.decrypt(cipher, aesKey.current, iv, 'aes-256-gcm');
      return decrypted;
    } catch (err) {
      throw new Error('Decryption error: ' + err.message);
    }
  };

  // Assemble chunks and save file
  const assembleAndSaveFile = async () => {
    try {
      const fileData = receivedChunks.current.join('');
      const filePath = `${RNFS.DocumentDirectoryPath}/received_file.txt`; // Example, adjust based on file type
      await RNFS.writeFile(filePath, fileData, 'base64');
      Alert.alert('File received', `File saved to ${filePath}`);
      setReceivedFileName('received_file.txt');
    } catch (err) {
      setError('File save error: ' + err.message);
    }
  };

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      manager.destroy();
    };
  }, [manager]);

  // Disconnect device
  const disconnectDevice = async () => {
    if (connectedDevice) {
      try {
        await manager.cancelDeviceConnection(connectedDevice.id);
      } catch (err) {
        // ignore
      }
      setConnectedDevice(null);
      setConnectionStatus('Disconnected');
      setReceivedFileName(null);
      setTransferProgress(0);
      receivedChunks.current = [];
      totalChunks.current = 0;
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.title}>Secure BLE File Receiver</Text>

      <View style={styles.section}>
        <Button
          title={isAdvertising ? 'Stop Advertising' : 'Start Advertising'}
          onPress={isAdvertising ? stopAdvertising : startAdvertising}
        />
        {isAdvertising && <ActivityIndicator style={{ marginTop: 8 }} />}
      </View>

      <View style={styles.section}>
        <Text style={styles.status}>Status: {connectionStatus}</Text>
        {connectedDevice && (
          <Button title="Disconnect" onPress={disconnectDevice} color="red" />
        )}
      </View>

      <View style={styles.section}>
        <Text style={styles.progress}>Progress: {transferProgress}%</Text>
        {receivedFileName && (
          <Text style={styles.fileInfo}>Received File: {receivedFileName}</Text>
        )}
      </View>

      {error && (
        <View style={styles.section}>
          <Text style={styles.error}>Error: {error}</Text>
        </View>
      )}
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
    backgroundColor: '#f5f5f5',
  },
  title: {
    fontSize: 22,
    fontWeight: 'bold',
    marginBottom: 12,
    textAlign: 'center',
  },
  section: {
    marginVertical: 8,
  },
  status: {
    fontSize: 16,
    marginBottom: 8,
  },
  progress: {
    marginTop: 6,
    fontSize: 16,
  },
  fileInfo: {
    marginTop: 6,
    fontSize: 14,
  },
  error: {
    color: 'red',
    fontWeight: 'bold',
  },
});

export default App;


