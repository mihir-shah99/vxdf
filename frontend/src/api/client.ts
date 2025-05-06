const API_BASE_URL = '/api';

interface ApiError extends Error {
  status?: number;
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const error: ApiError = new Error('API request failed');
    error.status = response.status;
    throw error;
  }
  return response.json();
}

export async function apiGet<T>(endpoint: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${endpoint}`);
  return handleResponse<T>(response);
}

export async function apiPost<T>(endpoint: string, data: unknown): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });
  return handleResponse<T>(response);
}

export async function apiPut<T>(endpoint: string, data: unknown): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });
  return handleResponse<T>(response);
}

export async function apiDelete<T>(endpoint: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: 'DELETE',
  });
  return handleResponse<T>(response);
} 