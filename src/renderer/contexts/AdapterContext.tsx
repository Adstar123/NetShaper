import React, { createContext, useContext, useState, ReactNode } from 'react';
import { NetworkAdapter, NetworkTopology } from '../../common/types';

interface AdapterContextType {
  selectedAdapter: NetworkAdapter | null;
  setSelectedAdapter: (adapter: NetworkAdapter | null) => void;
  isInitializing: boolean;
  setIsInitializing: (initializing: boolean) => void;
  isInitialized: boolean;
  setIsInitialized: (initialized: boolean) => void;
  topology: NetworkTopology | null;
  setTopology: (topology: NetworkTopology | null) => void;
}

const AdapterContext = createContext<AdapterContextType | undefined>(undefined);

interface AdapterProviderProps {
  children: ReactNode;
}

export const AdapterProvider: React.FC<AdapterProviderProps> = ({ children }) => {
  const [selectedAdapter, setSelectedAdapter] = useState<NetworkAdapter | null>(null);
  const [isInitializing, setIsInitializing] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);
  const [topology, setTopology] = useState<NetworkTopology | null>(null);

  const value: AdapterContextType = {
    selectedAdapter,
    setSelectedAdapter,
    isInitializing,
    setIsInitializing,
    isInitialized,
    setIsInitialized,
    topology,
    setTopology,
  };

  return (
    <AdapterContext.Provider value={value}>
      {children}
    </AdapterContext.Provider>
  );
};

export const useAdapter = (): AdapterContextType => {
  const context = useContext(AdapterContext);
  if (context === undefined) {
    throw new Error('useAdapter must be used within an AdapterProvider');
  }
  return context;
};

// Hook to check if actions should be disabled
export const useAdapterActions = () => {
  const { selectedAdapter, isInitializing, isInitialized } = useAdapter();
  
  const canPerformActions = selectedAdapter && !isInitializing && isInitialized;
  const disableActions = !canPerformActions;
  
  return {
    canPerformActions,
    disableActions,
    isAdapterReady: canPerformActions,
    selectedAdapter,
    isInitializing,
    isInitialized,
  };
};