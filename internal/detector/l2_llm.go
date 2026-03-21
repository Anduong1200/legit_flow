package detector

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// L2LLMDetector uses Gemini to detect contextually fuzzy PII like CCCD written in text
type L2LLMDetector struct {
	client *genai.Client
	model  *genai.GenerativeModel
}

// NewL2LLMDetector creates a new L2 LLM-based detector.
func NewL2LLMDetector(apiKey string) *L2LLMDetector {
	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		log.Printf("Cannot init GenAI client: %v", err)
		return nil
	}
	model := client.GenerativeModel("gemini-1.5-flash")
	model.ResponseMIMEType = "application/json"
	model.SystemInstruction = &genai.Content{
		Parts: []genai.Part{genai.Text(`Bạn là một Data Privacy Agent (AI DLP). Nhiệm vụ của bạn là phân tích văn bản, phát hiện chính xác thông tin định danh cá nhân (PII) - cụ thể là CMND (9 số) và CCCD Việt Nam (12 số).
QUY TẮC NHẬN DIỆN:
1. Nhận diện các dãy số có khả năng là CMND hoặc CCCD (chú ý trường hợp người dùng viết cách điệu như 079 090 123 456, 079-090-123456, hoặc viết lẫn lộn dấu chấm/cách).
2. TRÍCH XUẤT nguyên trạng đoạn text chứa cấu trúc đó ra. Không cần thay thế.
3. Nếu không có CMND/CCCD, trả về danh sách rỗng.
QUY TẮC ĐẦU RA (STRICT FORMAT):
Bạn CHỈ ĐƯỢC PHÉP trả về một mảng JSON các chuỗi (string) đại diện cho các PII tìm được. Ví dụ: ["079 090 123 456", "012345678"]`)},
	}
	return &L2LLMDetector{client: client, model: model}
}

func (d *L2LLMDetector) Name() string { return "l2_llm" }

// Detect scans text contextually using the LLM and maps the exact substring offsets.
func (d *L2LLMDetector) Detect(ctx context.Context, text string) ([]Detection, error) {
	if d.model == nil {
		return nil, nil // gracefully skip if not configured
	}

	resp, err := d.model.GenerateContent(ctx, genai.Text(text))
	if err != nil || len(resp.Candidates) == 0 {
		return nil, nil // Ignore failures to maintain gateway resiliency
	}

	part := resp.Candidates[0].Content.Parts[0]
	respStr, ok := part.(genai.Text)
	if !ok {
		return nil, nil
	}

	var found []string
	if err := json.Unmarshal([]byte(string(respStr)), &found); err != nil {
		return nil, nil // Ignore parse errors
	}

	var detections []Detection
	searchStart := 0

	for _, val := range found {
		if val == "" {
			continue
		}
		// Find index to set proper bounds for the native transformer
		idx := strings.Index(text[searchStart:], val)
		if idx != -1 {
			actualStart := searchStart + idx
			detections = append(detections, Detection{
				Type:       TypeCCCD,
				Tier:       TierRestricted,
				Value:      val,
				Start:      actualStart,
				End:        actualStart + len(val),
				Confidence: 0.9,
			})
			searchStart = actualStart + len(val)
		}
	}
	return detections, nil
}
