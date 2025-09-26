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
import DocumentPicker from 'react-native-document-picker';
import nacl from 'tweetnacl';
import { sha256 } from 'crypto-js';
import AES from 'react-native-aes-crypto';
import base64 from 'react-native-base64';

// Sample UUIDs for BLE service and characteristics
const SERVICE_UUID = '12345678-1234-5678-1234-56789abcdef0';
const HANDSHAKE_CHAR_UUID = '12345678-1234-5678-1234-56789abcdef1';
const TRANSFER_CHAR_UUID = '12345678-1234-5678-1234-56789abcdef2';

const CHUNK_SIZE = 180; // bytes per BLE payload chunk

const App = () => {
  const manager = useRef(new BleManager()).current;

  // State variables
  const [isScanning, setIsScanning] = useState(false);
  const [devices, setDevices] = useState([]);
  const [connectedDevice, setConnectedDevice] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('Disconnected');
  const [fileInfo, setFileInfo] = useState(null);
  const [transferProgress, setTransferProgress] = useState(0);
  const [error, setError] = useState(null);

  // Cryptographic keys and shared secret
  const ephemeralKeyPair = useRef(null);
  const sharedSecret = useRef(null);
  const aesKey = useRef(null);

  // BLE characteristics
  const handshakeChar = useRef(null);
  const transferChar = useRef(null);

  // ACK handling
  const ackReceived = useRef(true);

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

  // Scan for BLE devices
  const startScan = async () => {
    setError(null);
    const permission = await requestPermissions();
    if (!permission) return;

    setDevices([]);
    setIsScanning(true);
    setConnectionStatus('Scanning...');
    manager.startDeviceScan(null, null, (error, device) => {
      if (error) {
        setError('Scan error: ' + error.message);
        setIsScanning(false);
        setConnectionStatus('Disconnected');
        return;
      }
      if (device && device.name) {
        setDevices((prevDevices) => {
          if (prevDevices.find((d) => d.id === device.id)) {
            return prevDevices;
          }
          return [...prevDevices, device];
        });
      }
    });

    // Stop scanning after 10 seconds
    setTimeout(() => {
      manager.stopDeviceScan();
      setIsScanning(false);
      setConnectionStatus('Scan stopped');
    }, 10000);
  };

  // Connect to selected device
  const connectToDevice = async (device) => {
    setError(null);
    setConnectionStatus('Connecting...');
    try {
      const connected = await manager.connectToDevice(device.id);
      setConnectedDevice(connected);
      setConnectionStatus('Discovering services...');
      await connected.discoverAllServicesAndCharacteristics();

      // Get handshake and transfer characteristics
      const services = await connected.services();
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
        setError('Required BLE characteristics not found on device.');
        setConnectionStatus('Disconnected');
        await manager.cancelDeviceConnection(device.id);
        setConnectedDevice(null);
        return;
      }

      handshakeChar.current = handshakeCharacteristic;
      transferChar.current = transferCharacteristic;

      // Setup notification for ACKs on transfer characteristic
      await transferChar.current.monitor((error, characteristic) => {
        if (error) {
          setError('Notification error: ' + error.message);
          return;
        }
        if (characteristic?.value) {
          const value = base64.decode(characteristic.value);
          if (value === 'ACK') {
            ackReceived.current = true;
          }
        }
      });

      setConnectionStatus('Connected');

      // Generate ephemeral key pair and perform handshake
      await performKeyExchange();

    } catch (err) {
      setError('Connection error: ' + err.message);
      setConnectionStatus('Disconnected');
      setConnectedDevice(null);
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

      // Write our public key to handshake characteristic
      const pubKeyStr = base64.encode(String.fromCharCode(...ephemeralKeyPair.current.publicKey));
      await handshakeChar.current.writeWithResponse(pubKeyStr);

      // Read peer public key from handshake characteristic
      const peerPubChar = await handshakeChar.current.read();
      if (!peerPubChar?.value) {
        throw new Error('Failed to read peer public key');
      }
      const peerPubKeyStr = base64.decode(peerPubChar.value);
      const peerPubKeyUint8 = Uint8Array.from(peerPubKeyStr, (c) => c.charCodeAt(0));

      // Derive shared secret using nacl.box.before
      sharedSecret.current = nacl.box.before(peerPubKeyUint8, ephemeralKeyPair.current.secretKey);

      // Derive AES key using HKDF with SHA-256 on shared secret
      await deriveAESKey(sharedSecret.current);

    } catch (err) {
      setError('Key exchange error: ' + err.message);
      setConnectionStatus('Disconnected');
      if (connectedDevice) {
        await manager.cancelDeviceConnection(connectedDevice.id);
        setConnectedDevice(null);
      }
    }
  };

  // Derive AES-GCM key from shared secret using HKDF with SHA-256
  const deriveAESKey = async (sharedSecretUint8) => {
    try {
      // Convert Uint8Array to hex string
      const sharedSecretHex = Buffer.from(sharedSecretUint8).toString('hex');

      // Use crypto-js SHA256 as HKDF extract and expand (simplified)
      const hash = sha256(sharedSecretHex).toString();

      // Use first 32 bytes (64 hex chars) as AES key (256 bits)
      const aesKeyHex = hash.slice(0, 64);

      aesKey.current = aesKeyHex;
    } catch (err) {
      setError('AES key derivation error: ' + err.message);
    }
  };

  // Pick file using document picker
  const pickFile = async () => {
    setError(null);
    try {
      const res = await DocumentPicker.pickSingle({
        type: DocumentPicker.types.allFiles,
      });
      setFileInfo(res);
      setTransferProgress(0);
    } catch (err) {
      if (!DocumentPicker.isCancel(err)) {
        setError('File pick error: ' + err.message);
      }
    }
  };

  // Read file as base64 string
  const readFileAsBase64 = async (uri) => {
    try {
      const response = await fetch(uri);
      const blob = await response.blob();
      return await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onloadend = () => {
          const base64data = reader.result.split(',')[1];
          resolve(base64data);
        };
        reader.onerror = reject;
        reader.readAsDataURL(blob);
      });
    } catch (err) {
      throw new Error('File read error: ' + err.message);
    }
  };

  // Split base64 string into chunks of CHUNK_SIZE bytes (approximate)
  const chunkBase64String = (base64Str) => {
    const chunks = [];
    let index = 0;
    while (index < base64Str.length) {
      chunks.push(base64Str.slice(index, index + CHUNK_SIZE));
      index += CHUNK_SIZE;
    }
    return chunks;
  };

  // Encrypt chunk with AES-GCM
  const encryptChunk = async (chunkBase64) => {
    try {
      // Generate random IV (12 bytes)
      const iv = await AES.randomKey(12);
      // Encrypt chunkBase64 (string) with AES-GCM using aesKey.current (hex)
      const cipher = await AES.encrypt(chunkBase64, aesKey.current, iv, 'aes-256-gcm');
      // Return iv + cipher concatenated as base64 string
      return iv + cipher;
    } catch (err) {
      throw new Error('Encryption error: ' + err.message);
    }
  };

  // Send encrypted chunks sequentially with ACK handling
  const sendFileChunks = async () => {
    if (!fileInfo) {
      setError('No file selected');
      return;
    }
    if (!connectedDevice || !transferChar.current) {
      setError('No connected device or transfer characteristic');
      return;
    }
    if (!aesKey.current) {
      setError('Encryption key not established');
      return;
    }
    setError(null);
    setTransferProgress(0);

    try {
      const base64Data = await readFileAsBase64(fileInfo.uri);
      const chunks = chunkBase64String(base64Data);

      for (let i = 0; i < chunks.length; i++) {
        const encryptedChunk = await encryptChunk(chunks[i]);
        const encryptedChunkBase64 = base64.encode(encryptedChunk);

        // Wait for previous ACK
        while (!ackReceived.current) {
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
        ackReceived.current = false;

        // Write encrypted chunk to transfer characteristic (without response to speed up)
        await transferChar.current.writeWithoutResponse(encryptedChunkBase64);

        setTransferProgress(Math.round(((i + 1) / chunks.length) * 100));
      }

      Alert.alert('File transfer', 'File transfer completed successfully.');
    } catch (err) {
      setError('File transfer error: ' + err.message);
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
      setDevices([]);
      setFileInfo(null);
      setTransferProgress(0);
      setError(null);
    }
  };

  // Render device item
  const renderDeviceItem = ({ item }) => (
    <TouchableOpacity
      style={styles.deviceItem}
      onPress={() => connectToDevice(item)}
      disabled={!!connectedDevice}
    >
      <Text style={styles.deviceName}>{item.name}</Text>
      <Text style={styles.deviceId}>{item.id}</Text>
    </TouchableOpacity>
  );

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.title}>Secure BLE File Sender</Text>

      <View style={styles.section}>
        <Button
          title={isScanning ? 'Scanning...' : 'Scan Devices'}
          onPress={startScan}
          disabled={isScanning || !!connectedDevice}
        />
        {isScanning && <ActivityIndicator style={{ marginTop: 8 }} />}
      </View>

      <View style={styles.section}>
        <Text style={styles.status}>Status: {connectionStatus}</Text>
        {connectedDevice && (
          <Button title="Disconnect" onPress={disconnectDevice} color="red" />
        )}
      </View>

      <View style={styles.section}>
        <Text style={styles.subtitle}>Available Devices:</Text>
        <FlatList
          data={devices}
          keyExtractor={(item) => item.id}
          renderItem={renderDeviceItem}
          extraData={connectedDevice}
          style={styles.deviceList}
        />
      </View>

      <View style={styles.section}>
        <Button
          title="Pick File"
          onPress={pickFile}
          disabled={!connectedDevice}
        />
        {fileInfo && (
          <Text style={styles.fileInfo}>
            Selected File: {fileInfo.name} ({(fileInfo.size / 1024).toFixed(2)} KB)
          </Text>
        )}
      </View>

      <View style={styles.section}>
        <Button
          title="Send File"
          onPress={sendFileChunks}
          disabled={!fileInfo || !connectedDevice}
        />
        <Text style={styles.progress}>Progress: {transferProgress}%</Text>
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
  subtitle: {
    fontSize: 18,
    fontWeight: '600',
    marginBottom: 6,
  },
  deviceList: {
    maxHeight: 150,
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 6,
  },
  deviceItem: {
    padding: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#ddd',
  },
  deviceName: {
    fontSize: 16,
    fontWeight: '500',
  },
  deviceId: {
    fontSize: 12,
    color: '#666',
  },
  fileInfo: {
    marginTop: 6,
    fontSize: 14,
  },
  progress: {
    marginTop: 6,
    fontSize: 16,
  },
  error: {
    color: 'red',
    fontWeight: 'bold',
  },
});

export default App;
