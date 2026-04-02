import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ScanDetail from './pages/ScanDetail'
import NewScan from './pages/NewScan'
import Knowledgebase from './pages/Knowledgebase'
import Settings from './pages/Settings'
import Personas from './pages/Personas'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="scans/:scanId" element={<ScanDetail />} />
        <Route path="new-scan" element={<NewScan />} />
        <Route path="knowledgebase" element={<Knowledgebase />} />
        <Route path="settings" element={<Settings />} />
        <Route path="personas" element={<Personas />} />
      </Route>
    </Routes>
  )
}

export default App
