import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import AlertDetail from './pages/AlertDetail';
import Layout from './components/Layout';
import './App.css';

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alert/:id" element={<AlertDetail />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
