import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Vulnerabilities from './pages/Vulnerabilities';
import VulnerabilityDetail from './pages/VulnerabilityDetail';
import ValidationWorkflows from './pages/ValidationWorkflows';
import UploadScan from './pages/UploadScan';

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/vulnerabilities/:id" element={<VulnerabilityDetail />} />
        <Route path="/validation" element={<ValidationWorkflows />} />
        <Route path="/upload" element={<UploadScan />} />
      </Routes>
    </Layout>
  );
}

export default App; 