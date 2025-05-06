import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/layout/Layout';
import Dashboard from './components/dashboard/Dashboard';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;